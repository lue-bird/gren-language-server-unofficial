// lsp still reports this specific error even when it is allowed in the cargo.toml
#![allow(non_upper_case_globals)]

struct State {
    projects: std::collections::HashMap<
        /* path to directory containing gren.json */ std::path::PathBuf,
        ProjectState,
    >,
    open_gren_text_document_uris: std::collections::HashSet<lsp_types::Url>,
    configured_gren_path: Option<Box<str>>,
    configured_gren_formatter: Option<ConfiguredGrenFormatter>,
}
enum ConfiguredGrenFormatter {
    Builtin,
    Custom { path: Box<str> },
}

struct ProjectState {
    source_directories: Vec<std::path::PathBuf>,
    modules: std::collections::HashMap<std::path::PathBuf, ModuleState>,
    dependency_exposed_module_names: std::collections::HashMap<Box<str>, ProjectModuleOrigin>,
    gren_make_errors: Vec<GrenMakeFileCompileError>,
    kind: ProjectKind,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProjectKind {
    Dependency,
    InWorkspace,
}
#[derive(Debug, Clone)]
struct ProjectModuleOrigin {
    project_path: std::path::PathBuf,
    module_path: std::path::PathBuf,
}
struct ModuleState {
    syntax: GrenSyntaxModule,
    source: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, io_thread) = lsp_server::Connection::stdio();

    let (initialize_request_id, initialize_arguments_json) = connection.initialize_start()?;
    connection.initialize_finish(
        initialize_request_id,
        serde_json::to_value(lsp_types::InitializeResult {
            capabilities: server_capabilities(),
            server_info: Some(lsp_types::ServerInfo {
                name: "gren-language-server-unofficial".to_string(),
                version: Some("0.0.2".to_string()),
            }),
        })?,
    )?;
    let initialize_arguments: lsp_types::InitializeParams =
        serde_json::from_value(initialize_arguments_json)?;
    let state: State = initialize(&connection, &initialize_arguments)?;
    server_loop(&connection, state)?;
    // shut down gracefully
    drop(connection);
    io_thread.join()?;
    Ok(())
}
fn initialize(
    connection: &lsp_server::Connection,
    initialize_arguments: &lsp_types::InitializeParams,
) -> Result<State, Box<dyn std::error::Error>> {
    let mut state: State = State {
        projects: initialize_projects_state_for_workspace_directories_into(initialize_arguments),
        open_gren_text_document_uris: std::collections::HashSet::new(),
        configured_gren_path: None,
        configured_gren_formatter: None,
    };
    if let Some(config_json) = &initialize_arguments.initialization_options {
        update_state_with_configuration(&mut state, config_json);
    } else {
        connection
            .sender
            .send(lsp_server::Message::Request(configuration_request()?))?;
    }
    // only initializing diagnostics once the `grenPath` configuration is received would be better
    publish_and_initialize_state_for_diagnostics_for_projects_in_workspace(connection, &mut state);
    connection.sender.send(lsp_server::Message::Notification(
        lsp_server::Notification {
            method: <lsp_types::request::RegisterCapability as lsp_types::request::Request>::METHOD
                .to_string(),
            params: serde_json::to_value(lsp_types::RegistrationParams {
                registrations: initial_additional_capability_registrations(&state)?,
            })?,
        },
    ))?;
    Ok(state)
}
fn initial_additional_capability_registrations(
    state: &State,
) -> Result<Vec<lsp_types::Registration>, Box<dyn std::error::Error>> {
    let file_watch_registration_options: lsp_types::DidChangeWatchedFilesRegistrationOptions =
        lsp_types::DidChangeWatchedFilesRegistrationOptions {
            watchers: state
                .projects
                .values()
                .flat_map(|project| &project.source_directories)
                .filter_map(|source_directory_path| {
                    lsp_types::Url::from_directory_path(source_directory_path).ok()
                })
                .map(|source_directory_url| lsp_types::FileSystemWatcher {
                    glob_pattern: lsp_types::GlobPattern::Relative(lsp_types::RelativePattern {
                        base_uri: lsp_types::OneOf::Right(source_directory_url),
                        pattern: "**/{gren.json,*.gren}".to_string(),
                    }),
                    kind: Some(
                        lsp_types::WatchKind::Create
                            | lsp_types::WatchKind::Change
                            | lsp_types::WatchKind::Delete,
                    ),
                })
                .collect::<Vec<lsp_types::FileSystemWatcher>>(),
        };
    let file_watch_registration_options_json: serde_json::Value =
        serde_json::to_value(file_watch_registration_options)?;
    let file_watch_registration: lsp_types::Registration = lsp_types::Registration {
        id: "file-watch".to_string(),
        method: <lsp_types::notification::DidChangeWatchedFiles as lsp_types::notification::Notification>::METHOD.to_string(),
        register_options: Some(file_watch_registration_options_json),
    };
    let workspace_configuration_change_registration: lsp_types::Registration = lsp_types::Registration {
        id: "workspace-configuration".to_string(),
        method: <lsp_types::notification::DidChangeConfiguration as lsp_types::notification::Notification>::METHOD.to_string(),
        register_options: None,
    };
    Ok(vec![
        file_watch_registration,
        workspace_configuration_change_registration,
    ])
}
fn server_capabilities() -> lsp_types::ServerCapabilities {
    lsp_types::ServerCapabilities {
        hover_provider: Some(lsp_types::HoverProviderCapability::Simple(true)),
        definition_provider: Some(lsp_types::OneOf::Left(true)),
        semantic_tokens_provider: Some(
            lsp_types::SemanticTokensServerCapabilities::SemanticTokensOptions(
                lsp_types::SemanticTokensOptions {
                    work_done_progress_options: lsp_types::WorkDoneProgressOptions {
                        work_done_progress: None,
                    },
                    legend: lsp_types::SemanticTokensLegend {
                        token_modifiers: vec![],
                        token_types: Vec::from(token_types),
                    },
                    range: None,
                    full: Some(lsp_types::SemanticTokensFullOptions::Bool(true)),
                },
            ),
        ),
        text_document_sync: Some(lsp_types::TextDocumentSyncCapability::Kind(
            lsp_types::TextDocumentSyncKind::INCREMENTAL,
        )),
        rename_provider: Some(lsp_types::OneOf::Right(lsp_types::RenameOptions {
            prepare_provider: Some(true),
            work_done_progress_options: lsp_types::WorkDoneProgressOptions {
                work_done_progress: None,
            },
        })),
        references_provider: Some(lsp_types::OneOf::Left(true)),
        completion_provider: Some(lsp_types::CompletionOptions {
            resolve_provider: Some(false),
            trigger_characters: Some(vec![".".to_string()]),
            all_commit_characters: None,
            work_done_progress_options: lsp_types::WorkDoneProgressOptions {
                work_done_progress: None,
            },
            completion_item: Some(lsp_types::CompletionOptionsCompletionItem {
                label_details_support: None,
            }),
        }),
        document_formatting_provider: Some(lsp_types::OneOf::Left(true)),
        document_symbol_provider: Some(lsp_types::OneOf::Left(true)),
        code_action_provider: Some(lsp_types::CodeActionProviderCapability::Options(
            lsp_types::CodeActionOptions {
                code_action_kinds: Some(vec![lsp_types::CodeActionKind::QUICKFIX]),
                resolve_provider: None,
                work_done_progress_options: lsp_types::WorkDoneProgressOptions {
                    work_done_progress: None,
                },
            },
        )),
        ..lsp_types::ServerCapabilities::default()
    }
}
fn server_loop(
    connection: &lsp_server::Connection,
    mut state: State,
) -> Result<(), Box<dyn std::error::Error>> {
    for client_message in &connection.receiver {
        match client_message {
            lsp_server::Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    break;
                }
                if let Err(error) = handle_request(
                    connection,
                    &state,
                    request.id,
                    &request.method,
                    request.params,
                ) {
                    eprintln!("request {} failed: {error}", &request.method);
                }
            }
            lsp_server::Message::Notification(notification) => {
                if let Err(err) = handle_notification(
                    connection,
                    &mut state,
                    &notification.method,
                    notification.params,
                ) {
                    eprintln!("notification {} failed: {err}", notification.method);
                }
            }
            lsp_server::Message::Response(response) => {
                if let Err(err) = handle_response(&mut state, &response.id, response.result) {
                    eprintln!("failed to handle response {}: {err}", response.id);
                }
            }
        }
    }
    Ok(())
}
fn handle_notification(
    connection: &lsp_server::Connection,
    state: &mut State,
    notification_method: &str,
    notification_arguments_json: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    match notification_method {
        <lsp_types::notification::DidOpenTextDocument as lsp_types::notification::Notification>::METHOD => {
            let arguments: <lsp_types::notification::DidOpenTextDocument as lsp_types::notification::Notification>::Params =
                serde_json::from_value(notification_arguments_json)?;
            update_state_on_did_open_text_document(state, arguments);
        }
        <lsp_types::notification::DidCloseTextDocument as lsp_types::notification::Notification>::METHOD => {
            let arguments: <lsp_types::notification::DidCloseTextDocument as lsp_types::notification::Notification>::Params =
                serde_json::from_value(notification_arguments_json)?;
            state.open_gren_text_document_uris.remove(&arguments.text_document.uri);
        }
        <lsp_types::notification::DidChangeTextDocument as lsp_types::notification::Notification>::METHOD => {
            let arguments: <lsp_types::notification::DidChangeTextDocument as lsp_types::notification::Notification>::Params =
                serde_json::from_value(notification_arguments_json)?;
            update_state_on_did_change_text_document(state, arguments);
        }
        <lsp_types::notification::DidSaveTextDocument as lsp_types::notification::Notification>::METHOD => {
            let arguments: <lsp_types::notification::DidSaveTextDocument as lsp_types::notification::Notification>::Params =
                serde_json::from_value(notification_arguments_json)?;
            if let Ok(saved_path) = &arguments
                .text_document
                .uri
                .to_file_path()
                && let Some((saved_project_path, saved_project_state)) =
                    state_get_mut_project_by_module_path(&mut state.projects, saved_path)
            {
                publish_and_update_state_for_diagnostics_for_document(
                    connection,
                    state.configured_gren_path.as_deref(),
                    saved_project_path,
                    saved_project_state,
                    std::iter::empty(),
                );
            }
        }
        <lsp_types::notification::DidChangeWatchedFiles as lsp_types::notification::Notification>::METHOD => {
            let arguments: <lsp_types::notification::DidChangeWatchedFiles as lsp_types::notification::Notification>::Params =
                serde_json::from_value(notification_arguments_json)?;
            update_state_on_did_change_watched_files(connection, state, arguments);
        }
        <lsp_types::notification::DidChangeConfiguration as lsp_types::notification::Notification>::METHOD => {
            connection.sender.send(lsp_server::Message::Request(
                configuration_request()?
            ))?;
        }
        <lsp_types::notification::Exit as lsp_types::notification::Notification>::METHOD => {}
        _ => {}
    }
    Ok(())
}
fn update_state_on_did_open_text_document(
    state: &mut State,
    arguments: lsp_types::DidOpenTextDocumentParams,
) {
    // Why is the existing handling on DidChangeWatchedFiles not good enough?
    // When moving a module into an existing project,
    // no syntax highlighting would be shown before you interact with the file,
    // as semantic tokens are requested before the DidChangeWatchedFiles notification is sent.
    // Since DidOpenTextDocumentParams already sends the full file content anyway,
    // handling it on document open is relatively cheap and straightforward
    if let Ok(opened_path) = arguments.text_document.uri.to_file_path()
        && opened_path.extension().is_some_and(|ext| ext == "gren")
    {
        'adding_module_if_necessary: for project_state in state.projects.values_mut() {
            if project_state
                .source_directories
                .iter()
                .any(|source_dir| opened_path.starts_with(source_dir))
            {
                project_state.modules.entry(opened_path).or_insert_with(|| {
                    initialize_module_state_from_source(arguments.text_document.text)
                });
                break 'adding_module_if_necessary;
            }
        }
        state
            .open_gren_text_document_uris
            .insert(arguments.text_document.uri);
    }
}
fn update_state_on_did_change_watched_files(
    connection: &lsp_server::Connection,
    state: &mut State,
    mut arguments: lsp_types::DidChangeWatchedFilesParams,
) {
    arguments.changes.retain(|file_event| {
        // exclude changes to opened documents are already handled by DidChangeTextDocument.
        // Then why listen to DidChangeWatchedFiles at all?
        // E.g. go to definition needs an up to date module syntax tree
        // in a potentially un-opened file that could have been changed externally,
        // e.g. by formatting, generating code, ...
        !(file_event.typ == lsp_types::FileChangeType::CHANGED
            && state.open_gren_text_document_uris.contains(&file_event.uri))
    });
    if arguments.changes.is_empty() {
        return;
    }
    let mut edited_gren_json_project_paths: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    for (project_path, project_state) in state.projects.iter_mut() {
        let mut project_was_updated: bool = false;
        let mut removed_paths: Vec<lsp_types::Url> = Vec::new();
        for (file_change_uri, changed_file_path, file_change_type) in
            arguments.changes.iter().filter_map(|file_change_event| {
                match file_change_event.uri.to_file_path() {
                    Ok(changed_file_path) => Some((
                        &file_change_event.uri,
                        changed_file_path,
                        file_change_event.typ,
                    )),
                    Err(()) => None,
                }
            })
        {
            if path_is_gren_json_in_project_path(project_path, &changed_file_path) {
                edited_gren_json_project_paths.insert(project_path.clone());
            } else if changed_file_path
                .extension()
                .is_some_and(|ext| ext == "gren")
                && project_state
                    .source_directories
                    .iter()
                    .any(|source_dir| changed_file_path.starts_with(source_dir))
            {
                match file_change_type {
                    lsp_types::FileChangeType::DELETED => {
                        if project_state.modules.remove(&changed_file_path).is_some() {
                            project_was_updated = true;
                            removed_paths.push(file_change_uri.clone());
                        }
                    }
                    lsp_types::FileChangeType::CREATED | lsp_types::FileChangeType::CHANGED => {
                        match std::fs::read_to_string(&changed_file_path) {
                            Err(_) => {}
                            Ok(changed_file_source) => {
                                project_was_updated = true;
                                project_state.modules.insert(
                                    changed_file_path,
                                    initialize_module_state_from_source(changed_file_source),
                                );
                            }
                        }
                    }
                    unknown_file_change_type => {
                        eprintln!(
                            "unknown file change type sent by LSP client: {:?}",
                            unknown_file_change_type
                        );
                    }
                }
            }
        }
        if project_was_updated {
            publish_and_update_state_for_diagnostics_for_document(
                connection,
                state.configured_gren_path.as_deref(),
                project_path,
                project_state,
                removed_paths.into_iter(),
            );
        }
    }
    if !edited_gren_json_project_paths.is_empty() {
        update_projects_state_on_gren_json_changes(
            &mut state.projects,
            edited_gren_json_project_paths.into_iter(),
        );
    }
}
fn update_projects_state_on_gren_json_changes(
    projects_state: &mut std::collections::HashMap<std::path::PathBuf, ProjectState>,
    edited_gren_json_project_paths: impl Iterator<Item = std::path::PathBuf>,
) {
    // can be optimized by keeping more of the existing state
    // and skipping collecting info about uninitialized projects for already initialized projects
    let mut uninitialized_projects: std::collections::HashMap<std::path::PathBuf, ProjectState> =
        std::collections::HashMap::new();
    initialize_state_for_all_projects_into(
        &mut uninitialized_projects,
        edited_gren_json_project_paths,
    );
    for (uninitialized_project_path, uninitialized_project) in uninitialized_projects {
        match projects_state.get_mut(&uninitialized_project_path) {
            Some(project_state_to_update) => {
                match project_state_to_update.kind {
                    ProjectKind::Dependency => {
                        // will be the same, no need to initialize again
                    }
                    ProjectKind::InWorkspace => {
                        // in case dependencies were added or removed,
                        // the only thing that changes are the available dependency modules
                        project_state_to_update.dependency_exposed_module_names =
                            uninitialized_project.dependency_exposed_module_names;
                    }
                }
            }
            None => {
                projects_state.insert(
                    uninitialized_project_path,
                    ProjectState {
                        modules: initialize_project_modules(
                            uninitialized_project.modules.into_keys(),
                        ),
                        source_directories: uninitialized_project.source_directories,
                        dependency_exposed_module_names: uninitialized_project
                            .dependency_exposed_module_names,
                        gren_make_errors: uninitialized_project.gren_make_errors,
                        kind: uninitialized_project.kind,
                    },
                );
            }
        }
    }
}
fn path_is_gren_json_in_project_path(
    project_path: &std::path::Path,
    path_to_check: &std::path::Path,
) -> bool {
    path_to_check.parent() == Some(project_path)
        && path_to_check
            .file_name()
            .is_some_and(|name| name == "gren.json")
}
fn configuration_request() -> Result<lsp_server::Request, Box<dyn std::error::Error>> {
    let requested_configuration: <lsp_types::request::WorkspaceConfiguration as lsp_types::request::Request>::Params =
        lsp_types::ConfigurationParams {
            items: vec![
                lsp_types::ConfigurationItem {
                    scope_uri: None,
                    section: Some("gren-language-server-unofficial".to_string())
                }
            ]
        };
    Ok(lsp_server::Request {
        id: lsp_server::RequestId::from(ServerRequestId::WorkspaceConfiguration as i32),
        method: <lsp_types::request::WorkspaceConfiguration as lsp_types::request::Request>::METHOD
            .to_string(),
        params: serde_json::to_value(requested_configuration)?,
    })
}
enum ServerRequestId {
    WorkspaceConfiguration,
}
fn handle_response(
    state: &mut State,
    response_id: &lsp_server::RequestId,
    maybe_response_result: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    if response_id == &lsp_server::RequestId::from(ServerRequestId::WorkspaceConfiguration as i32)
        && let Some(response_result) = maybe_response_result
    {
        let response_parsed: <lsp_types::request::WorkspaceConfiguration as lsp_types::request::Request>::Result =
            serde_json::from_value(response_result)?;
        if let Some(config_json) = response_parsed.first() {
            update_state_with_configuration(state, config_json);
        }
    }
    Ok(())
}
fn handle_request(
    connection: &lsp_server::Connection,
    state: &State,
    request_id: lsp_server::RequestId,
    request_method: &str,
    request_arguments_json: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let response: Result<serde_json::Value, lsp_server::ResponseError> = match request_method {
        <lsp_types::request::HoverRequest as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::HoverRequest as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let maybe_hover_result: <lsp_types::request::HoverRequest as lsp_types::request::Request>::Result =
                respond_to_hover(state, &arguments);
            Ok(serde_json::to_value(maybe_hover_result)?)
        }
        <lsp_types::request::GotoDefinition as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::GotoDefinition as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let maybe_hover_result: <lsp_types::request::GotoDefinition as lsp_types::request::Request>::Result =
                respond_to_goto_definition(state, arguments);
            Ok(serde_json::to_value(maybe_hover_result)?)
        }
        <lsp_types::request::PrepareRenameRequest as lsp_types::request::Request>::METHOD => {
            let prepare_rename_arguments: <lsp_types::request::PrepareRenameRequest as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let prepared: Option<
                Result<lsp_types::PrepareRenameResponse, lsp_server::ResponseError>,
            > = respond_to_prepare_rename(state, &prepare_rename_arguments);
            let response_result: Result<
                <lsp_types::request::PrepareRenameRequest as lsp_types::request::Request>::Result,
                lsp_server::ResponseError,
            > = match prepared {
                None => Ok(None),
                Some(result) => result.map(Some),
            };
            match response_result {
                Err(error) => Err(error),
                Ok(maybe_response) => Ok(serde_json::to_value(maybe_response)?),
            }
        }
        <lsp_types::request::Rename as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::Rename as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let maybe_rename_edits: Option<Vec<lsp_types::TextDocumentEdit>> =
                respond_to_rename(state, arguments);
            let result: <lsp_types::request::Rename as lsp_types::request::Request>::Result =
                maybe_rename_edits.map(|rename_edits| lsp_types::WorkspaceEdit {
                    changes: None,
                    document_changes: Some(lsp_types::DocumentChanges::Edits(rename_edits)),
                    change_annotations: None,
                });
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::References as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::References as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::References as lsp_types::request::Request>::Result =
                respond_to_references(state, arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::SemanticTokensFullRequest as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::SemanticTokensFullRequest as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::SemanticTokensFullRequest as lsp_types::request::Request>::Result =
                respond_to_semantic_tokens_full(state, &arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::Completion as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::Completion as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::Completion as lsp_types::request::Request>::Result =
                respond_to_completion(state, &arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::Formatting as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::Formatting as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::Formatting as lsp_types::request::Request>::Result =
                respond_to_document_formatting(state, &arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::DocumentSymbolRequest as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::DocumentSymbolRequest as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::DocumentSymbolRequest as lsp_types::request::Request>::Result =
                respond_to_document_symbols(state, &arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::CodeActionRequest as lsp_types::request::Request>::METHOD => {
            let arguments: <lsp_types::request::CodeActionRequest as lsp_types::request::Request>::Params =
                serde_json::from_value(request_arguments_json)?;
            let result: <lsp_types::request::CodeActionRequest as lsp_types::request::Request>::Result =
                respond_to_code_action(state, arguments);
            Ok(serde_json::to_value(result)?)
        }
        <lsp_types::request::Shutdown as lsp_types::request::Request>::METHOD => {
            let result: <lsp_types::request::Shutdown as lsp_types::request::Request>::Result = ();
            Ok(serde_json::to_value(result)?)
        }
        _ => Err(lsp_server::ResponseError {
            code: lsp_server::ErrorCode::MethodNotFound as i32,
            message: "unhandled method".to_string(),
            data: None,
        }),
    };
    match response {
        Ok(response_value) => {
            send_response_ok(connection, request_id, response_value)?;
        }
        Err(response_error) => send_response_error(connection, request_id, response_error)?,
    }
    Ok(())
}

fn send_response_ok(
    connection: &lsp_server::Connection,
    id: lsp_server::RequestId,
    result: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let response: lsp_server::Response = lsp_server::Response {
        id,
        result: Some(result),
        error: None,
    };
    connection
        .sender
        .send(lsp_server::Message::Response(response))?;
    Ok(())
}
fn send_response_error(
    connection: &lsp_server::Connection,
    id: lsp_server::RequestId,
    error: lsp_server::ResponseError,
) -> Result<(), Box<dyn std::error::Error>> {
    let response: lsp_server::Response = lsp_server::Response {
        id,
        result: None,
        error: Some(error),
    };
    connection
        .sender
        .send(lsp_server::Message::Response(response))?;
    Ok(())
}
fn publish_diagnostics(
    connection: &lsp_server::Connection,
    diagnostics: <lsp_types::notification::PublishDiagnostics as lsp_types::notification::Notification>::Params,
) -> Result<(), Box<dyn std::error::Error>> {
    connection.sender.send(lsp_server::Message::Notification(
        lsp_server::Notification {
            method: <lsp_types::notification::PublishDiagnostics as lsp_types::notification::Notification>::METHOD.to_string(),
            params: serde_json::to_value(diagnostics)?,
        },
    ))?;
    Ok(())
}

fn update_state_on_did_change_text_document(
    state: &mut State,
    did_change_text_document: lsp_types::DidChangeTextDocumentParams,
) {
    let Ok(changed_file_path) = did_change_text_document.text_document.uri.to_file_path() else {
        return;
    };
    for project_state in state.projects.values_mut() {
        if let Some(module_state) = project_state.modules.get_mut(&changed_file_path) {
            for change in did_change_text_document.content_changes {
                match (change.range, change.range_length) {
                    (None, None) => {
                        // means full replacement
                        project_state.modules.insert(
                            changed_file_path,
                            initialize_module_state_from_source(change.text),
                        );
                        return;
                    }
                    (Some(range), Some(range_length)) => {
                        string_replace_lsp_range(
                            &mut module_state.source,
                            range,
                            range_length as usize,
                            &change.text,
                        );
                    }
                    (None, _) | (_, None) => {}
                }
            }
            module_state.syntax = parse_gren_syntax_module(&module_state.source);
            break;
        }
    }
}

fn publish_and_initialize_state_for_diagnostics_for_projects_in_workspace(
    connection: &lsp_server::Connection,
    state: &mut State,
) {
    for (in_workspace_project_path, in_workspace_project_state) in
        state
            .projects
            .iter_mut()
            .filter(|(_, project)| match project.kind {
                ProjectKind::InWorkspace => true,
                ProjectKind::Dependency => false,
            })
    {
        match compute_diagnostics(
            state.configured_gren_path.as_deref(),
            in_workspace_project_path,
            in_workspace_project_state,
        ) {
            Err(error) => {
                eprintln!("{error}");
            }
            Ok(gren_make_errors) => {
                let diagnostics_to_publish: Vec<lsp_types::PublishDiagnosticsParams> =
                    gren_make_errors
                        .iter()
                        .filter_map(|gren_make_file_error| {
                            let url: lsp_types::Url =
                                lsp_types::Url::from_file_path(gren_make_file_error.path.as_ref())
                                    .ok()?;
                            let diagnostics: Vec<lsp_types::Diagnostic> = gren_make_file_error
                                .problems
                                .iter()
                                .map(gren_make_file_problem_to_diagnostic)
                                .collect::<Vec<_>>();
                            Some(lsp_types::PublishDiagnosticsParams {
                                uri: url,
                                diagnostics: diagnostics,
                                version: None,
                            })
                        })
                        .collect::<Vec<_>>();
                for file_diagnostics_to_publish in diagnostics_to_publish {
                    let _ = publish_diagnostics(connection, file_diagnostics_to_publish);
                }
                in_workspace_project_state.gren_make_errors = gren_make_errors;
            }
        }
    }
}

fn publish_and_update_state_for_diagnostics_for_document(
    connection: &lsp_server::Connection,
    configured_gren_path: Option<&str>,
    project_path: &std::path::Path,
    project: &mut ProjectState,
    removed_paths: impl Iterator<Item = lsp_types::Url>,
) {
    match compute_diagnostics(configured_gren_path, project_path, project) {
        Err(error) => {
            eprintln!("{error}");
        }
        Ok(gren_make_errors) => {
            let mut updated_diagnostics_to_publish: Vec<lsp_types::PublishDiagnosticsParams> =
                Vec::new();
            for gren_make_file_error in project.modules.keys() {
                // O(modules*errors), might be problematic in large projects
                let maybe_new = gren_make_errors
                    .iter()
                    .find(|&file_error| file_error.path.as_ref() == gren_make_file_error);
                let maybe_updated_diagnostics = match maybe_new {
                    Some(new) => {
                        let diagnostics: Vec<lsp_types::Diagnostic> = new
                            .problems
                            .iter()
                            .map(gren_make_file_problem_to_diagnostic)
                            .collect::<Vec<_>>();
                        Some(diagnostics)
                    }
                    None => {
                        let was_error: bool = project
                            .gren_make_errors
                            .iter()
                            .any(|file_error| file_error.path.as_ref() == gren_make_file_error);
                        if was_error { Some(vec![]) } else { None }
                    }
                };
                if let Some(updated_diagnostics) = maybe_updated_diagnostics
                    && let Ok(url) = lsp_types::Url::from_file_path(gren_make_file_error)
                {
                    updated_diagnostics_to_publish.push(lsp_types::PublishDiagnosticsParams {
                        uri: url,
                        diagnostics: updated_diagnostics,
                        version: None,
                    });
                }
            }
            for removed_url in removed_paths {
                updated_diagnostics_to_publish.push(lsp_types::PublishDiagnosticsParams {
                    uri: removed_url,
                    diagnostics: vec![],
                    version: None,
                });
            }
            for updated_file_diagnostics_to_publish in updated_diagnostics_to_publish {
                let _ = publish_diagnostics(connection, updated_file_diagnostics_to_publish);
            }
            project.gren_make_errors = gren_make_errors;
        }
    }
}

fn compute_diagnostics(
    configured_gren_path: Option<&str>,
    project_path: &std::path::Path,
    project_state: &ProjectState,
) -> Result<Vec<GrenMakeFileCompileError>, String> {
    if !std::path::Path::exists(project_path) {
        // project zombie. Probably got deleted
        return Ok(vec![]);
    }
    // if there is a better way, please open an issue <3
    let sink_path: &str = match std::env::consts::FAMILY {
        "windows" => "NUL",
        _ => "/dev/null",
    };
    let compiler_executable_name: &str = configured_gren_path.unwrap_or("gren");
    let project_module_names = project_state.modules.values().filter_map(|module_state| {
        module_state
            .syntax
            .header
            .as_ref()
            .and_then(|header| header.module_name.as_ref())
            .map(|name_node| name_node.value.as_ref())
    });
    let mut gren_make_command: std::process::Command =
        std::process::Command::new(compiler_executable_name);
    gren_make_command.args(
        std::iter::once("make")
            .chain(project_module_names)
            .chain(["--report=json", &format!("--output={sink_path}")]),
    );
    gren_make_command.current_dir(project_path);
    gren_make_command.stdin(std::process::Stdio::null());
    gren_make_command.stdout(std::process::Stdio::piped());
    gren_make_command.stderr(std::process::Stdio::piped());
    let gren_make_process: std::process::Child = gren_make_command
        .spawn().map_err(|error| {
            format!(
                "I tried to run {} but it failed: {error}. Try installing gren via `npm install -g gren-lang`.",
                format!("{gren_make_command:?}").replace('"', "")
            )
        })?;
    let gren_make_output: std::process::Output = gren_make_process
        .wait_with_output()
        .map_err(|error| format!("I wasn't able to read the output of gren make: {error}"))?;
    Ok(if gren_make_output.stderr.is_empty() {
        vec![]
    } else {
        let gren_make_report_json: serde_json::Value =
            serde_json::from_slice(&gren_make_output.stderr).map_err(|parse_error| {
                format!(
                    "failed to parse gren make report json: {parse_error}, full text: {}",
                    str::from_utf8(&gren_make_output.stderr).unwrap_or("")
                )
            })?;
        parse_gren_make_report(&gren_make_report_json)?
    })
}
#[derive(Debug)]
struct GrenMakeFileCompileError {
    path: Box<str>,
    problems: Vec<GrenMakeFileInternalCompileProblem>,
}
#[derive(Debug)]
struct GrenMakeFileInternalCompileProblem {
    title: Box<str>,
    range: lsp_types::Range,
    message_markdown: String,
}
#[derive(Debug, Clone, Copy)]
enum GrenMakeMessageSegment<'a> {
    Plain(&'a str),
    Colored {
        underline: bool,
        bold: bool,
        color: Option<&'a str>,
        text: &'a str,
    },
}

fn gren_make_message_segments_to_markdown(
    gren_make_message_segments: Vec<GrenMakeMessageSegment>,
) -> String {
    let mut builder: String = String::new();
    for gren_make_message_segment in gren_make_message_segments {
        match gren_make_message_segment {
            GrenMakeMessageSegment::Plain(text) => {
                builder.push_str(text);
            }
            GrenMakeMessageSegment::Colored {
                underline,
                bold,
                color: maybe_color,
                text,
            } => {
                // https://github.com/microsoft/vscode/issues/54272
                if let Some(_color) = maybe_color {
                    builder.push_str(text);
                } else if bold || underline {
                    builder.push_str(&text.to_ascii_uppercase());
                } else {
                    // suspicious, would have expected ::Plain
                    builder.push_str(text);
                }
            }
        }
    }
    builder
}

fn parse_gren_make_report(
    json: &serde_json::Value,
) -> Result<Vec<GrenMakeFileCompileError>, String> {
    match json.get("type").and_then(serde_json::Value::as_str) {
        Some("compile-errors") => match json.get("errors") {
            Some(serde_json::Value::Array(file_error_jsons)) => file_error_jsons
                .iter()
                .map(parse_gren_make_file_compile_error)
                .collect::<Result<Vec<_>, String>>(),
            _ => Err("field errors must be array".to_string()),
        },
        Some(unknown_type) => Err(format!("unknown report type {unknown_type}")),
        None => Err("report type must exist as a string".to_string()),
    }
}
fn parse_gren_make_file_compile_error(
    json: &serde_json::Value,
) -> Result<GrenMakeFileCompileError, String> {
    let path: &str = json
        .get("path")
        .and_then(serde_json::Value::as_str)
        .ok_or("report file path must be string")?;
    let problems: Vec<GrenMakeFileInternalCompileProblem> = json
        .get("problems")
        .and_then(serde_json::Value::as_array)
        .ok_or("field problems must exist as array")?
        .iter()
        .map(parse_gren_make_file_internal_compile_problem)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GrenMakeFileCompileError {
        path: Box::from(path),
        problems: problems,
    })
}
fn parse_gren_make_file_internal_compile_problem(
    json: &serde_json::Value,
) -> Result<GrenMakeFileInternalCompileProblem, String> {
    let title: &str = json
        .get("title")
        .and_then(serde_json::Value::as_str)
        .ok_or("report file path must be string")?;
    let range: lsp_types::Range = json
        .get("region")
        .ok_or_else(|| "report file region must be string".to_string())
        .and_then(parse_gren_make_region_as_lsp_range)?;
    let message_segments: Vec<GrenMakeMessageSegment> = json
        .get("message")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "report file message must be an array".to_string())?
        .iter()
        .map(parse_gren_make_message_segment)
        .collect::<Result<Vec<GrenMakeMessageSegment>, _>>()?;
    Ok(GrenMakeFileInternalCompileProblem {
        title: Box::from(title),
        range: range,
        message_markdown: gren_make_message_segments_to_markdown(message_segments),
    })
}
fn parse_gren_make_region_as_lsp_range(
    json: &serde_json::Value,
) -> Result<lsp_types::Range, String> {
    let start: lsp_types::Position = json
        .get("start")
        .ok_or_else(|| "file region must have start".to_string())
        .and_then(parse_gren_make_position_as_lsp_position)?;
    let end: lsp_types::Position = json
        .get("end")
        .ok_or_else(|| "file region must have end".to_string())
        .and_then(parse_gren_make_position_as_lsp_position)?;
    Ok(lsp_types::Range {
        start: start,
        end: end,
    })
}
fn parse_gren_make_position_as_lsp_position(
    json: &serde_json::Value,
) -> Result<lsp_types::Position, String> {
    let line_1_based: i64 = json
        .get("line")
        .and_then(serde_json::Value::as_i64)
        .ok_or("file region line must be integer")?;
    let column_1_based: i64 = json
        .get("column")
        .and_then(serde_json::Value::as_i64)
        .ok_or("file region column must be integer")?;
    Ok(lsp_types::Position {
        line: (line_1_based - 1) as u32,
        character: (column_1_based - 1) as u32,
    })
}
fn parse_gren_make_message_segment<'a>(
    json: &'a serde_json::Value,
) -> Result<GrenMakeMessageSegment<'a>, String> {
    match json {
        serde_json::Value::String(plain) => Ok(GrenMakeMessageSegment::Plain(plain)),
        serde_json::Value::Object(fields_json) => {
            let text: &str = fields_json
                .get("string")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("report file problem message segment string must be string, all fields: {json}"))?;
            let color: Option<&str> = fields_json.get("color").and_then(serde_json::Value::as_str);
            let underline: bool = fields_json
                .get("underline")
                .and_then(serde_json::Value::as_bool)
                .ok_or("report file problem message segment underline must be string")?;
            let bold: bool = fields_json
                .get("bold")
                .and_then(serde_json::Value::as_bool)
                .ok_or("report file problem message segment bold must be string")?;
            Ok(GrenMakeMessageSegment::Colored {
                underline: underline,
                bold: bold,
                color: color,
                text: text,
            })
        }
        _ => Err(format!(
            "unknown report file problem message segment {json}"
        )),
    }
}
fn update_state_with_configuration(state: &mut State, config_json: &serde_json::Value) {
    state.configured_gren_path = config_json
        .get("grenPath")
        .and_then(|path_json| path_json.as_str())
        .and_then(|path| {
            if path.is_empty() {
                None
            } else {
                Some(Box::from(path))
            }
        });
    state.configured_gren_formatter = config_json
        .get("grenFormatPath")
        .and_then(|path_json| path_json.as_str())
        .and_then(|path| {
            if path.is_empty() {
                None
            } else {
                Some(if path == "builtin" {
                    ConfiguredGrenFormatter::Builtin
                } else {
                    ConfiguredGrenFormatter::Custom {
                        path: Box::from(path),
                    }
                })
            }
        });
}
fn initialize_projects_state_for_workspace_directories_into(
    initialize_arguments: &lsp_types::InitializeParams,
) -> std::collections::HashMap<std::path::PathBuf, ProjectState> {
    let mut projects_state: std::collections::HashMap<std::path::PathBuf, ProjectState> =
        std::collections::HashMap::new();
    let workspace_directory_paths = initialize_arguments
        .workspace_folders
        .iter()
        .flatten()
        .filter_map(|workspace_folder| workspace_folder.uri.to_file_path().ok());
    initialize_state_for_all_projects_into(
        &mut projects_state,
        list_gren_project_directories_in_directory_at_path(workspace_directory_paths).into_iter(),
    );
    let (fully_parsed_project_sender, fully_parsed_project_receiver) = std::sync::mpsc::channel();
    std::thread::scope(|thread_scope| {
        for (uninitialized_project_path, uninitialized_project_state) in &projects_state {
            let projects_that_finished_full_parse_sender = fully_parsed_project_sender.clone();
            thread_scope.spawn(move || {
                projects_that_finished_full_parse_sender.send((
                    uninitialized_project_path.clone(),
                    initialize_project_modules(uninitialized_project_state.modules.keys().cloned()),
                ))
            });
        }
    });
    drop(fully_parsed_project_sender);
    while let Ok((fully_parsed_project_path, fully_parsed_project_modules)) =
        fully_parsed_project_receiver.recv()
    {
        if let Some(project_state_to_update) = projects_state.get_mut(&fully_parsed_project_path) {
            project_state_to_update.modules = fully_parsed_project_modules;
        }
    }
    projects_state
}
fn initialize_project_modules(
    uninitialized_module_paths: impl Iterator<Item = std::path::PathBuf>,
) -> std::collections::HashMap<std::path::PathBuf, ModuleState> {
    let mut fully_parsed_modules: std::collections::HashMap<std::path::PathBuf, ModuleState> =
        std::collections::HashMap::new();
    for uninitialized_module_path in uninitialized_module_paths {
        if let Ok(module_source) = std::fs::read_to_string(&uninitialized_module_path) {
            fully_parsed_modules.insert(
                uninitialized_module_path,
                initialize_module_state_from_source(module_source),
            );
        }
    }
    fully_parsed_modules
}

fn initialize_state_for_all_projects_into(
    projects_state: &mut std::collections::HashMap<std::path::PathBuf, ProjectState>,
    project_paths: impl Iterator<Item = std::path::PathBuf>,
) {
    let gren_home_path: std::path::PathBuf = match std::env::var("GREN_HOME") {
        Ok(gren_home_path) => std::path::PathBuf::from(gren_home_path),
        Err(_) => {
            std::path::Path::join(
                &std::env::home_dir()
                    .unwrap_or_else(|| {
                        eprintln!(
                            "I could not find an gren home directory (expected to find $HOME/.cache/gren or $GREN_HOME environment variable).
This directory has cached information about installed packages like gren-lang/core and is therefore required by this language server.
Running `gren` commands should create that directory.
This language server from now assumes there exists a local .gren directory.
If that is where you actually put installed gren packages, make sure to set the $GREN_HOME environment variable
accordingly so that tools like the gren compiler and language server can find them."
                        );
                        std::env::current_dir().ok().unwrap_or_else(|| std::path::PathBuf::new())
                    }),
                ".cache/gren",
            )
        }
    };
    let mut all_dependency_exposed_module_names: std::collections::HashMap<
        std::path::PathBuf,
        std::collections::HashMap<Box<str>, ProjectModuleOrigin>,
    > = std::collections::HashMap::new();
    let mut skipped_dependencies: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    for project_path in project_paths {
        initialize_state_for_project_into(
            projects_state,
            &mut all_dependency_exposed_module_names,
            &mut skipped_dependencies,
            &gren_home_path,
            ProjectKind::InWorkspace,
            project_path,
        );
    }
    if !skipped_dependencies.is_empty() {
        eprintln!(
            "I will skip initializing these dependencies {}: {}. \n  \
            I can only load packages that you've actively downloaded with `gren install`. \
            If you did and don't care about LSP functionality for indirect dependencies, ignore this message.",
            if skipped_dependencies.len() == 1 {
                "project"
            } else {
                "projects"
            },
            skipped_dependencies
                .into_iter()
                .map(|dep| dep.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}
/// returns exposed module names and their origins
fn initialize_state_for_projects_into(
    projects_state: &mut std::collections::HashMap<std::path::PathBuf, ProjectState>,
    all_dependency_exposed_module_names: &mut std::collections::HashMap<
        std::path::PathBuf,
        std::collections::HashMap<Box<str>, ProjectModuleOrigin>,
    >,
    skipped_dependencies: &mut std::collections::HashSet<std::path::PathBuf>,
    gren_home_path: &std::path::PathBuf,
    project_kind: ProjectKind,
    project_paths: impl Iterator<Item = std::path::PathBuf>,
) -> std::collections::HashMap<Box<str>, ProjectModuleOrigin> {
    let mut dependency_exposed_module_names: std::collections::HashMap<
        Box<str>,
        ProjectModuleOrigin,
    > = std::collections::HashMap::new();
    for project_path in project_paths {
        dependency_exposed_module_names.extend(initialize_state_for_project_into(
            projects_state,
            all_dependency_exposed_module_names,
            skipped_dependencies,
            gren_home_path,
            project_kind,
            project_path,
        ));
    }
    dependency_exposed_module_names
}
fn initialize_state_for_project_into(
    projects_state: &mut std::collections::HashMap<std::path::PathBuf, ProjectState>,
    all_dependency_exposed_module_names: &mut std::collections::HashMap<
        std::path::PathBuf,
        std::collections::HashMap<Box<str>, ProjectModuleOrigin>,
    >,
    skipped_dependencies: &mut std::collections::HashSet<std::path::PathBuf>,
    gren_home_path: &std::path::PathBuf,
    project_kind: ProjectKind,
    project_path: std::path::PathBuf,
) -> std::collections::HashMap<Box<str>, ProjectModuleOrigin> {
    if let Some(project_exposed_module_names) =
        all_dependency_exposed_module_names.get(&project_path)
    {
        return project_exposed_module_names.clone();
    }
    let gren_json_path: std::path::PathBuf = std::path::Path::join(&project_path, "gren.json");
    let maybe_gren_json_value: Option<serde_json::Value> = std::fs::read_to_string(&gren_json_path)
        .ok()
        .and_then(|gren_json_source| {
            serde_json::from_str(&gren_json_source)
                .map_err(|json_parse_error: serde_json::Error| {
                    eprintln!("I couldn't read this gren.json as JSON: {json_parse_error}");
                })
                .ok()
        });
    let maybe_gren_json: Option<GrenJson> =
        maybe_gren_json_value.as_ref().and_then(|gren_json_value| {
            parse_gren_json(gren_json_value)
                .map_err(|json_decode_error| {
                    eprintln!(
                        "I couldn't understand this gren.json: {}",
                        json_decode_error
                    );
                })
                .ok()
        });
    if maybe_gren_json.is_none() {
        match project_kind {
            ProjectKind::InWorkspace => {
                eprintln!(
                    "I couldn't find a valid gren.json found at path {gren_json_path:?}. Now looking for gren module files across the workspace and gren-lang/core 7.2.1"
                );
            }
            ProjectKind::Dependency => {
                skipped_dependencies.insert(project_path);
                return std::collections::HashMap::new();
            }
        }
    }
    let gren_json_source_directories: Vec<std::path::PathBuf> = match &maybe_gren_json {
        None => {
            vec![project_path.clone()]
        }
        Some(GrenJson::Application {
            source_directories,
            direct_dependencies: _,
        }) => source_directories
            .iter()
            .copied()
            .map(|relative| std::path::Path::join(&project_path, relative))
            .collect::<Vec<_>>(),
        Some(GrenJson::Package { .. }) => vec![std::path::Path::join(&project_path, "src")],
    };
    let dependency_path = |package_name: &str, package_version: &str| {
        std::path::Path::join(
            gren_home_path,
            format!(
                "0.6.3/packages/{}__{}",
                package_name.replace('/', "_"),
                package_version.replace('.', "_")
            ),
        )
    };
    let direct_dependency_paths: Vec<std::path::PathBuf> = match &maybe_gren_json {
        None => vec![dependency_path("gren-lang/core", "7.2.1")],
        Some(GrenJson::Application {
            direct_dependencies,
            source_directories: _,
        }) => direct_dependencies
            .iter()
            .map(|(name, version)| dependency_path(name, version))
            .collect::<Vec<_>>(),
        Some(GrenJson::Package {
            dependency_minimum_versions,
            exposed_modules: _,
        }) => dependency_minimum_versions
            .iter()
            .map(|(n, v)| dependency_path(n, v))
            .collect::<Vec<_>>(),
    };
    let module_states: std::collections::HashMap<std::path::PathBuf, ModuleState> =
        list_gren_files_in_directory_at_paths(gren_json_source_directories.iter().cloned())
            .into_iter()
            .map(|module_path| (module_path, uninitialized_module_state))
            .collect::<std::collections::HashMap<_, _>>();
    let mut exposed_module_names: std::collections::HashMap<Box<str>, ProjectModuleOrigin> =
        std::collections::HashMap::new();
    if let Some(GrenJson::Package {
        exposed_modules,
        dependency_minimum_versions: _,
    }) = &maybe_gren_json
    {
        for &exposed_module_name in exposed_modules {
            let maybe_module_origin_path: Option<&std::path::PathBuf> =
                module_states.keys().find(|module_path| {
                    derive_module_name_from_path(&gren_json_source_directories, module_path)
                        .is_some_and(|derived_module_name| {
                            derived_module_name == exposed_module_name
                        })
                });
            if let Some(module_origin_path) = maybe_module_origin_path {
                exposed_module_names.insert(
                    Box::from(exposed_module_name),
                    ProjectModuleOrigin {
                        project_path: project_path.clone(),
                        module_path: module_origin_path.clone(),
                    },
                );
            }
        }
    }
    let direct_dependency_exposed_module_names: std::collections::HashMap<
        Box<str>,
        ProjectModuleOrigin,
    > = initialize_state_for_projects_into(
        projects_state,
        all_dependency_exposed_module_names,
        skipped_dependencies,
        gren_home_path,
        ProjectKind::Dependency,
        direct_dependency_paths.into_iter(),
    );
    projects_state.insert(
        project_path.clone(),
        ProjectState {
            kind: project_kind,
            source_directories: gren_json_source_directories,
            modules: module_states,
            dependency_exposed_module_names: direct_dependency_exposed_module_names,
            gren_make_errors: vec![],
        },
    );
    if !exposed_module_names.is_empty() {
        all_dependency_exposed_module_names.insert(project_path, exposed_module_names.clone());
    }
    exposed_module_names
}
/// A yet to be initialized dummy [`ModuleState`]
const uninitialized_module_state: ModuleState = ModuleState {
    source: String::new(),
    syntax: GrenSyntaxModule {
        header: None,
        documentation: None,
        comments: vec![],
        imports: vec![],
        declarations: vec![],
    },
};
fn initialize_module_state_from_source(source: String) -> ModuleState {
    ModuleState {
        syntax: parse_gren_syntax_module(&source),
        source: source,
    }
}
enum GrenJson<'a> {
    Application {
        source_directories: Vec<&'a str>,
        direct_dependencies: std::collections::HashMap<&'a str, &'a str>,
    },
    Package {
        dependency_minimum_versions: std::collections::HashMap<&'a str, &'a str>,
        exposed_modules: Vec<&'a str>,
    },
}

fn parse_gren_json<'a>(json: &'a serde_json::Value) -> Result<GrenJson<'a>, String> {
    let json_object: &serde_json::Map<String, serde_json::Value> = match json {
        serde_json::Value::Object(json_object) => Ok(json_object),
        _ => Err("must be an object".to_string()),
    }?;
    match json_object.get("type") {
        Some(serde_json::Value::String(type_string)) => match type_string.as_str() {
            "application" => {
                let direct_dependencies: std::collections::HashMap<&str, &str> = match json_object
                    .get("dependencies")
                    .and_then(|dependencies| dependencies.get("direct"))
                {
                    Some(serde_json::Value::Object(direct_dependencies_json)) => {
                        let mut direct_dependencies: std::collections::HashMap<&str, &str> =
                            std::collections::HashMap::new();
                        for (direct_dependency_name, direct_dependency_version_json) in
                            direct_dependencies_json
                        {
                            let direct_dependency_version: &str =
                                match direct_dependency_version_json {
                                    serde_json::Value::String(v) => Ok(v.as_str()),
                                    _ => Err(format!(
                                        "{direct_dependency_name} dependency version must be a string"
                                    )),
                                }?;
                            direct_dependencies
                                .insert(direct_dependency_name.as_str(), direct_dependency_version);
                        }
                        Ok::<std::collections::HashMap<&str, &str>, String>(direct_dependencies)
                    }
                    _ => Err("must have field dependencies.direct".to_string()),
                }?;
                let mut source_directories: Vec<&str> = Vec::new();
                match json_object.get("source-directories") {
                    Some(serde_json::Value::Array(source_directories_json)) => {
                        for source_directory_json in source_directories_json {
                            match source_directory_json {
                                serde_json::Value::String(source_directory) => {
                                    source_directories.push(source_directory);
                                }
                                _ => {
                                    return Err(
                                        "source directories must be all strings".to_string()
                                    );
                                }
                            }
                        }
                    }
                    _ => return Err("must have field source-directories".to_string()),
                }
                Ok(GrenJson::Application {
                    source_directories: source_directories,
                    direct_dependencies: direct_dependencies,
                })
            }
            "package" => {
                let dependency_minimum_versions: std::collections::HashMap<&str, &str> =
                    match json_object.get("dependencies") {
                        Some(serde_json::Value::Object(dependencies)) => {
                            let mut dependency_minimum_versions: std::collections::HashMap<
                                &str,
                                &str,
                            > = std::collections::HashMap::new();
                            for (direct_dependency_name, direct_dependency_version_json) in
                                dependencies
                            {
                                let dependency_version_minimum: &str =
                                    match direct_dependency_version_json {
                                        serde_json::Value::String(
                                            dependency_version_constraint,
                                        ) => gren_json_version_constraint_to_minimum_version(
                                            dependency_version_constraint,
                                        ),
                                        _ => Err(format!(
                                            "{direct_dependency_name} dependency version must be a string"
                                        )),
                                    }?;
                                dependency_minimum_versions.insert(
                                    direct_dependency_name.as_str(),
                                    dependency_version_minimum,
                                );
                            }
                            Ok(dependency_minimum_versions)
                        }
                        _ => Err("must have field dependencies".to_string()),
                    }?;
                let mut exposed_modules: Vec<&str> = Vec::new();
                match json_object.get("exposed-modules") {
                    Some(serde_json::Value::Array(source_directories_json)) => {
                        for source_directory_json in source_directories_json {
                            match source_directory_json {
                                serde_json::Value::String(source_directory) => {
                                    exposed_modules.push(source_directory);
                                }
                                _ => {
                                    return Err("exposed modules must be all strings".to_string());
                                }
                            }
                        }
                    }
                    Some(serde_json::Value::Object(grouped)) => {
                        for group_values in grouped.values() {
                            match group_values {
                                serde_json::Value::Array(source_directories_json) => {
                                    for source_directory_json in source_directories_json {
                                        match source_directory_json {
                                            serde_json::Value::String(source_directory) => {
                                                exposed_modules.push(source_directory);
                                            }
                                            _ => {
                                                return Err("exposed modules must be all strings"
                                                    .to_string());
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    return Err("exposed module group must be an array".to_string());
                                }
                            }
                        }
                    }
                    _ => return Err("must have field exposed-modules".to_string()),
                }
                Ok(GrenJson::Package {
                    dependency_minimum_versions,
                    exposed_modules: exposed_modules,
                })
            }
            _ => Err("field type must be package or application".to_string()),
        },
        _ => Err("must have field type".to_string()),
    }
}
fn gren_json_version_constraint_to_minimum_version(
    gren_json_version_constraint: &str,
) -> Result<&str, String> {
    match gren_json_version_constraint.split_once(" <= v < ") {
        None => Err(format!(
            "dependency version constraints must be set in the form lo <= v < hi, found {gren_json_version_constraint}"
        )),
        Some((minimum_version, _maximum_version)) => {
            if !minimum_version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
            {
                Err(format!(
                    "dependency version constraint minimum version must only be composed of digits and .s, found: {minimum_version}"
                ))
            } else {
                Ok(minimum_version)
            }
        }
    }
}

fn project_state_get_module_with_name<'a>(
    state: &'a State,
    project_state: &'a ProjectState,
    module_name: &str,
) -> Option<(&'a std::path::PathBuf, &'a ModuleState)> {
    match project_state
        .dependency_exposed_module_names
        .get(module_name)
    {
        Some(dependency_module_origin) => state
            .projects
            .get(&dependency_module_origin.project_path)
            .and_then(|dependency| {
                dependency
                    .modules
                    .get_key_value(&dependency_module_origin.module_path)
            }),
        None => project_state
            .modules
            .iter()
            .find_map(|(module_path, module_state)| {
                if module_state
                    .syntax
                    .header
                    .as_ref()
                    .is_some_and(|header_node| {
                        header_node
                            .module_name
                            .as_ref()
                            .is_some_and(|module_name_node| {
                                module_name_node.value.as_ref() == module_name
                            })
                    })
                {
                    Some((module_path, module_state))
                } else {
                    None
                }
            }),
    }
}
#[derive(Clone, Copy)]
struct ProjectModuleState<'a> {
    project_path: &'a std::path::Path,
    project: &'a ProjectState,
    module: &'a ModuleState,
}

fn state_get_project_module_by_lsp_url<'a>(
    state: &'a State,
    uri: &lsp_types::Url,
) -> Option<ProjectModuleState<'a>> {
    let file_path: std::path::PathBuf = uri.to_file_path().ok()?;
    state_get_project_module_by_path(state, &file_path)
}
fn state_get_project_module_by_path<'a>(
    state: &'a State,
    file_path: &std::path::PathBuf,
) -> Option<ProjectModuleState<'a>> {
    state
        .projects
        .iter()
        .find_map(|(project_path, project_state)| {
            let module_state = project_state.modules.get(file_path)?;
            Some(ProjectModuleState {
                project_path: project_path,
                project: project_state,
                module: module_state,
            })
        })
}
fn state_get_mut_project_by_module_path<'a>(
    projects: &'a mut std::collections::HashMap<std::path::PathBuf, ProjectState>,
    file_path: &std::path::PathBuf,
) -> Option<(&'a std::path::PathBuf, &'a mut ProjectState)> {
    projects
        .iter_mut()
        .find_map(|(project_path, project_state)| {
            if project_state.modules.contains_key(file_path) {
                Some((project_path, project_state))
            } else {
                None
            }
        })
}
fn respond_to_hover(
    state: &State,
    hover_arguments: &lsp_types::HoverParams,
) -> Option<lsp_types::Hover> {
    let hovered_project_module_state = state_get_project_module_by_lsp_url(
        state,
        &hover_arguments
            .text_document_position_params
            .text_document
            .uri,
    )?;
    let hovered_symbol_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &hovered_project_module_state.module.syntax,
            hover_arguments.text_document_position_params.position,
        )?;
    match hovered_symbol_node.value {
        GrenSyntaxSymbol::TypeVariable { .. } => None,
        GrenSyntaxSymbol::ModuleName(hovered_module_name)
        | GrenSyntaxSymbol::ImportAlias {
            module_origin: hovered_module_name,
            alias_name: _,
        } => {
            let (origin_module_path, origin_module_state) = project_state_get_module_with_name(
                state,
                hovered_project_module_state.project,
                hovered_module_name,
            )?;
            let origin_module_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_path).ok()?;
            // also show list of exports maybe?
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: match &origin_module_state.syntax.documentation {
                        None => "_module has no documentation comment_".to_string(),
                        Some(module_documentation) => gren_syntax_module_documentation_to_markdown(
                            &origin_module_url,
                            &origin_module_state.syntax,
                            &module_documentation.value,
                        ),
                    },
                }),
                range: Some(hovered_symbol_node.range),
            })
        }
        GrenSyntaxSymbol::ModuleHeaderExpose {
            name: hovered_name,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name: hovered_name,
            module_documentation: _,
        } => {
            let hovered_module_origin: &str = hovered_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let origin_module_origin_lookup: ModuleOriginLookup =
                gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &hovered_project_module_state.module.syntax,
                );
            let origin_declaration_info_markdown: String = hovered_project_module_state
                .module
                .syntax
                .declarations
                .iter()
                .find_map(|documented_declaration_or_err| {
                    let documented_declaration = documented_declaration_or_err.as_ref().ok()?;
                    let declaration_node = documented_declaration.declaration.as_ref()?;
                    match &declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: origin_module_declaration_name,
                            parameters: origin_module_declaration_parameters,
                            equals_key_symbol_range: _,
                            variant0_name: origin_module_declaration_variant0_name_node,
                            variant0_value: origin_module_declaration_variant0_maybe_value,
                            variant1_up: origin_module_declaration_variant1_up,
                        } => {
                            if origin_module_declaration_name
                                .as_ref()
                                .map(|node| node.value.as_ref())
                                == Some(hovered_name)
                            {
                                Some(present_choice_type_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state
                                        .module
                                        .syntax
                                        .comments,
                                    declaration_node.range,
                                    origin_module_declaration_name
                                        .as_ref()
                                        .map(gren_syntax_node_unbox),
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    origin_module_declaration_parameters,
                                    origin_module_declaration_variant0_name_node
                                        .as_ref()
                                        .map(gren_syntax_node_unbox),
                                    origin_module_declaration_variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                                    origin_module_declaration_variant1_up,
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator {
                            direction: maybe_declaration_direction,
                            precedence: maybe_declaration_precedence,
                            operator: maybe_declaration_operator,
                            equals_key_symbol_range: _,
                            function: maybe_declaration_function,
                        } => {
                            if maybe_declaration_operator.as_ref().map(|node| node.value)
                                == Some(hovered_name)
                            {
                                let maybe_origin_operator_function_declaration =
                                    maybe_declaration_function.as_ref().and_then(
                                        |origin_module_declaration_function_node| {
                                            hovered_project_module_state
                                                .module
                                                .syntax
                                                .declarations
                                                .iter()
                                                .find_map(|origin_module_declaration_or_err| {
                                                    let origin_module_declaration = origin_module_declaration_or_err.as_ref().ok()?;
                                                    let origin_module_declaration_node =
                                                        origin_module_declaration
                                                            .declaration
                                                            .as_ref()?;
                                                    match &origin_module_declaration_node.value {
                                                        GrenSyntaxDeclaration::Variable {
                                                            start_name: origin_module_declaration_name,
                                                            signature: origin_module_declaration_signature,
                                                            parameters: _,
                                                            equals_key_symbol_range: _,
                                                            result: _,
                                                        } if origin_module_declaration_name.value
                                                            == origin_module_declaration_function_node
                                                                .value =>
                                                        {
                                                            Some((
                                                                origin_module_declaration_signature
                                                                    .as_ref(),
                                                                origin_module_declaration
                                                                    .documentation
                                                                    .as_ref()
                                                                    .map(|node| node.value.as_ref()),
                                                            ))
                                                        }
                                                        _ => None,
                                                    }
                                                })
                                        },
                                    );
                                Some(present_operator_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    maybe_declaration_operator.as_ref().map(|node| node.value),
                                    maybe_origin_operator_function_declaration,
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    maybe_declaration_direction.map(|node| node.value),
                                    maybe_declaration_precedence.map(|node| node.value),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Port {
                            name: maybe_declaration_name,
                            colon_key_symbol_range: _,
                            type_,
                        } => {
                            if let Some(declaration_name_node) = maybe_declaration_name &&
                                declaration_name_node.value.as_ref() == hovered_name
                            {
                                Some(present_port_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    declaration_node.range,
                                    Some(gren_syntax_node_unbox(declaration_name_node)),
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias {
                            alias_keyword_range: _,
                            name: maybe_declaration_name,
                            parameters: origin_module_declaration_parameters,
                            equals_key_symbol_range: _,
                            type_,
                        } => {
                            if let Some(declaration_name_node) = maybe_declaration_name.as_ref() &&
                               declaration_name_node.value.as_ref() == hovered_name
                            {
                                Some(present_type_alias_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    declaration_node.range,
                                    Some(gren_syntax_node_unbox(declaration_name_node)),
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    origin_module_declaration_parameters,
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Variable {
                            start_name: declaration_name_node,
                            signature: declaration_maybe_signature,
                            parameters: _,
                            equals_key_symbol_range: _,
                            result: _,
                        } => {
                            if declaration_name_node.value.as_ref() == hovered_name {
                                Some(present_variable_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    gren_syntax_node_unbox(declaration_name_node),
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    declaration_maybe_signature.as_ref().and_then(|signature| {
                                        signature.type_.as_ref().map(gren_syntax_node_as_ref)
                                    }),
                                ))
                            } else {
                                None
                            }
                        }
                    }
                })?;
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: origin_declaration_info_markdown,
                }),
                range: Some(hovered_symbol_node.range),
            })
        }
        GrenSyntaxSymbol::ModuleMemberDeclarationName {
            name: hovered_declaration_name,
            documentation,
            declaration: declaration_node,
        } => {
            let hovered_module_origin: &str = hovered_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let origin_module_origin_lookup: ModuleOriginLookup =
                gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &hovered_project_module_state.module.syntax,
                );
            let origin_declaration_info_markdown: String = match &declaration_node.value {
                GrenSyntaxDeclaration::ChoiceType {
                    name: origin_module_declaration_name,
                    parameters: origin_module_declaration_parameters,
                    equals_key_symbol_range: _,
                    variant0_name: origin_module_declaration_variant0_name_node,
                    variant0_value: origin_module_declaration_variant0_maybe_value,
                    variant1_up: origin_module_declaration_variant1_up,
                } => {
                    format!(
                        "{}{}",
                        if Some(hovered_declaration_name)
                            == origin_module_declaration_name
                                .as_ref()
                                .map(|node| node.value.as_ref())
                        {
                            ""
                        } else {
                            "variant in\n"
                        },
                        &present_choice_type_declaration_info_markdown(
                            &origin_module_origin_lookup,
                            hovered_module_origin,
                            &hovered_project_module_state.module.syntax.comments,
                            declaration_node.range,
                            origin_module_declaration_name
                                .as_ref()
                                .map(gren_syntax_node_unbox),
                            documentation,
                            origin_module_declaration_parameters,
                            origin_module_declaration_variant0_name_node
                                .as_ref()
                                .map(gren_syntax_node_unbox),
                            origin_module_declaration_variant0_maybe_value
                                .as_ref()
                                .map(gren_syntax_node_as_ref),
                            origin_module_declaration_variant1_up,
                        )
                    )
                }
                GrenSyntaxDeclaration::Operator {
                    direction: maybe_origin_module_declaration_direction,
                    precedence: maybe_origin_module_declaration_precedence,
                    operator: maybe_origin_module_declaration_operator,
                    equals_key_symbol_range: _,
                    function: maybe_origin_module_declaration_function,
                } => {
                    let maybe_origin_operator_function_declaration =
                        maybe_origin_module_declaration_function.as_ref().and_then(
                            |origin_module_declaration_function_node| {
                                hovered_project_module_state
                                    .module
                                    .syntax
                                    .declarations
                                    .iter()
                                    .find_map(|origin_module_declaration_or_err| {
                                        let origin_module_declaration =
                                            origin_module_declaration_or_err.as_ref().ok()?;
                                        let origin_module_declaration_node =
                                            origin_module_declaration.declaration.as_ref()?;
                                        match &origin_module_declaration_node.value {
                                            GrenSyntaxDeclaration::Variable {
                                                start_name: origin_module_declaration_name,
                                                signature: origin_module_declaration_signature,
                                                parameters: _,
                                                equals_key_symbol_range: _,
                                                result: _,
                                            } if origin_module_declaration_name.value
                                                == origin_module_declaration_function_node
                                                    .value =>
                                            {
                                                Some((
                                                    origin_module_declaration_signature.as_ref(),
                                                    origin_module_declaration
                                                        .documentation
                                                        .as_ref()
                                                        .map(|node| node.value.as_ref()),
                                                ))
                                            }
                                            _ => None,
                                        }
                                    })
                            },
                        );
                    present_operator_declaration_info_markdown(
                        &origin_module_origin_lookup,
                        hovered_module_origin,
                        maybe_origin_module_declaration_operator
                            .as_ref()
                            .map(|node| node.value),
                        maybe_origin_operator_function_declaration,
                        documentation,
                        maybe_origin_module_declaration_direction.map(|node| node.value),
                        maybe_origin_module_declaration_precedence.map(|node| node.value),
                    )
                }
                GrenSyntaxDeclaration::Port {
                    name: maybe_declaration_name,
                    colon_key_symbol_range: _,
                    type_,
                } => present_port_declaration_info_markdown(
                    &origin_module_origin_lookup,
                    hovered_module_origin,
                    &hovered_project_module_state.module.syntax.comments,
                    declaration_node.range,
                    maybe_declaration_name.as_ref().map(gren_syntax_node_unbox),
                    documentation,
                    type_.as_ref().map(gren_syntax_node_as_ref),
                ),
                GrenSyntaxDeclaration::TypeAlias {
                    alias_keyword_range: _,
                    name: maybe_declaration_name,
                    parameters: origin_module_declaration_parameters,
                    equals_key_symbol_range: _,
                    type_,
                } => present_type_alias_declaration_info_markdown(
                    &origin_module_origin_lookup,
                    hovered_module_origin,
                    &hovered_project_module_state.module.syntax.comments,
                    declaration_node.range,
                    maybe_declaration_name.as_ref().map(gren_syntax_node_unbox),
                    documentation,
                    origin_module_declaration_parameters,
                    type_.as_ref().map(gren_syntax_node_as_ref),
                ),
                GrenSyntaxDeclaration::Variable {
                    start_name: origin_module_declaration_name_node,
                    signature: origin_module_declaration_maybe_signature,
                    parameters: _,
                    equals_key_symbol_range: _,
                    result: _,
                } => present_variable_declaration_info_markdown(
                    &origin_module_origin_lookup,
                    hovered_module_origin,
                    &hovered_project_module_state.module.syntax.comments,
                    gren_syntax_node_unbox(origin_module_declaration_name_node),
                    documentation,
                    origin_module_declaration_maybe_signature
                        .as_ref()
                        .and_then(|signature| signature.type_.as_ref())
                        .map(gren_syntax_node_as_ref),
                ),
            };
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: origin_declaration_info_markdown,
                }),
                range: Some(hovered_symbol_node.range),
            })
        }

        GrenSyntaxSymbol::ImportExpose {
            name: hovered_name,
            origin_module: hovered_expose_origin_module,
            all_exposes: _,
        } => {
            let hovered_module_origin: &str = hovered_expose_origin_module;
            let (_, origin_module_state) = project_state_get_module_with_name(
                state,
                hovered_project_module_state.project,
                hovered_module_origin,
            )?;
            let origin_module_origin_lookup: ModuleOriginLookup =
                gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &origin_module_state.syntax,
                );
            let origin_declaration_info_markdown: String =
                origin_module_state.syntax.declarations.iter().find_map(
                    |documented_declaration_or_err| {
                        let documented_declaration = documented_declaration_or_err.as_ref().ok()?;
                        let declaration_node = documented_declaration.declaration.as_ref()?;
                        match &declaration_node.value {
                            GrenSyntaxDeclaration::ChoiceType {
                                name: origin_module_declaration_name,
                                parameters: origin_module_declaration_parameters,
                                equals_key_symbol_range: _,
                                variant0_name: origin_module_declaration_variant0_name_node,
                                variant0_value: origin_module_declaration_variant0_maybe_value,
                                variant1_up: origin_module_declaration_variant1_up,
                            } => {
                                if origin_module_declaration_name
                                    .as_ref()
                                    .map(|node| node.value.as_ref())
                                    == Some(hovered_name)
                                {
                                    Some(present_choice_type_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        &hovered_project_module_state.module.syntax.comments,
                                        declaration_node.range,
                                        origin_module_declaration_name
                                            .as_ref()
                                            .map(gren_syntax_node_unbox),
                                        documented_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        origin_module_declaration_parameters,
                                        origin_module_declaration_variant0_name_node
                                            .as_ref()
                                            .map(gren_syntax_node_unbox),
                                        origin_module_declaration_variant0_maybe_value
                                            .as_ref()
                                            .map(gren_syntax_node_as_ref),
                                        origin_module_declaration_variant1_up,
                                    ))
                                } else {
                                    None
                                }
                            }
                            GrenSyntaxDeclaration::Operator {
                                direction: maybe_declaration_direction,
                                precedence: maybe_declaration_precedence,
                                operator: maybe_declaration_operator,
                                equals_key_symbol_range: _,
                                function: maybe_declaration_function,
                            } => {
                                if maybe_declaration_operator.as_ref().map(|node| node.value)
                                    == Some(hovered_name)
                                {
                                    let maybe_origin_operator_function_declaration =
                                    maybe_declaration_function.as_ref().and_then(
                                        |origin_module_declaration_function_node| {
                                            origin_module_state.syntax.declarations.iter().find_map(
                                                |origin_module_declaration_or_err| {
                                                    let origin_module_declaration =
                                                        origin_module_declaration_or_err
                                                            .as_ref()
                                                            .ok()?;
                                                    let origin_module_declaration_node =
                                                        origin_module_declaration
                                                            .declaration
                                                            .as_ref()?;
                                                    match &origin_module_declaration_node.value {
                                                GrenSyntaxDeclaration::Variable {
                                                    start_name: origin_module_declaration_name,
                                                    signature: origin_module_declaration_signature,
                                                    parameters: _,
                                                    equals_key_symbol_range: _,
                                                    result: _,
                                                } if origin_module_declaration_name.value
                                                    == origin_module_declaration_function_node
                                                        .value =>
                                                {
                                                    Some((
                                                        origin_module_declaration_signature
                                                            .as_ref(),
                                                        origin_module_declaration
                                                            .documentation
                                                            .as_ref()
                                                            .map(|node| node.value.as_ref()),
                                                    ))
                                                }
                                                _ => None,
                                            }
                                                },
                                            )
                                        },
                                    );
                                    Some(present_operator_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        maybe_declaration_operator.as_ref().map(|node| node.value),
                                        maybe_origin_operator_function_declaration,
                                        documented_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        maybe_declaration_direction.map(|node| node.value),
                                        maybe_declaration_precedence.map(|node| node.value),
                                    ))
                                } else {
                                    None
                                }
                            }
                            GrenSyntaxDeclaration::Port {
                                name: maybe_declaration_name,
                                colon_key_symbol_range: _,
                                type_,
                            } => {
                                if let Some(declaration_name_node) = maybe_declaration_name
                                    && declaration_name_node.value.as_ref() == hovered_name
                                {
                                    Some(present_port_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        &hovered_project_module_state.module.syntax.comments,
                                        declaration_node.range,
                                        Some(gren_syntax_node_unbox(declaration_name_node)),
                                        documented_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        type_.as_ref().map(gren_syntax_node_as_ref),
                                    ))
                                } else {
                                    None
                                }
                            }
                            GrenSyntaxDeclaration::TypeAlias {
                                alias_keyword_range: _,
                                name: maybe_declaration_name,
                                parameters: origin_module_declaration_parameters,
                                equals_key_symbol_range: _,
                                type_,
                            } => {
                                if let Some(declaration_name_node) = maybe_declaration_name
                                    && declaration_name_node.value.as_ref() == hovered_name
                                {
                                    Some(present_type_alias_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        &hovered_project_module_state.module.syntax.comments,
                                        declaration_node.range,
                                        Some(gren_syntax_node_unbox(declaration_name_node)),
                                        documented_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        origin_module_declaration_parameters,
                                        type_.as_ref().map(gren_syntax_node_as_ref),
                                    ))
                                } else {
                                    None
                                }
                            }
                            GrenSyntaxDeclaration::Variable {
                                start_name: declaration_name_node,
                                signature: declaration_maybe_signature,
                                parameters: _,
                                equals_key_symbol_range: _,
                                result: _,
                            } => {
                                if declaration_name_node.value.as_ref() == hovered_name {
                                    Some(present_variable_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        &hovered_project_module_state.module.syntax.comments,
                                        gren_syntax_node_unbox(declaration_name_node),
                                        documented_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        declaration_maybe_signature
                                            .as_ref()
                                            .and_then(|signature| signature.type_.as_ref())
                                            .map(gren_syntax_node_as_ref),
                                    ))
                                } else {
                                    None
                                }
                            }
                        }
                    },
                )?;
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: origin_declaration_info_markdown,
                }),
                range: Some(hovered_symbol_node.range),
            })
        }
        GrenSyntaxSymbol::LetDeclarationName {
            name: hovered_name,
            signature_type: maybe_signature_type,
            start_name_range,
            scope_expression: _,
        } => Some(lsp_types::Hover {
            contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: let_declaration_info_markdown(
                    state,
                    hovered_project_module_state.project,
                    &hovered_project_module_state.module.syntax,
                    GrenSyntaxNode {
                        range: start_name_range,
                        value: hovered_name,
                    },
                    maybe_signature_type,
                ),
            }),
            range: Some(hovered_symbol_node.range),
        }),
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification: hovered_qualification,
            name: hovered_name,
            local_bindings,
        } => {
            if hovered_qualification.is_empty()
                && let Some((hovered_local_binding_origin, _)) =
                    find_local_binding_scope_expression(&local_bindings, hovered_name)
            {
                return Some(lsp_types::Hover {
                    contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                        kind: lsp_types::MarkupKind::Markdown,
                        value: local_binding_info_markdown(
                            state,
                            hovered_project_module_state.project,
                            &hovered_project_module_state.module.syntax,
                            hovered_name,
                            hovered_local_binding_origin,
                        ),
                    }),
                    range: Some(hovered_symbol_node.range),
                });
            }
            let hovered_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &hovered_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: hovered_qualification,
                    name: hovered_name,
                },
            );
            let (_, origin_module_state) = project_state_get_module_with_name(
                state,
                hovered_project_module_state.project,
                hovered_module_origin,
            )?;
            let origin_module_origin_lookup: ModuleOriginLookup =
                gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &origin_module_state.syntax,
                );
            let origin_declaration_info_markdown: String =
                origin_module_state
                .syntax
                .declarations
                .iter()
                .find_map(|origin_module_declaration_or_err| {
                    let origin_module_declaration = origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node = origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: origin_module_declaration_name,
                            parameters: origin_module_declaration_parameters,
                            equals_key_symbol_range: _,
                            variant0_name: origin_module_declaration_variant0_name_node,
                            variant0_value: origin_module_declaration_variant0_maybe_value,
                            variant1_up: origin_module_declaration_variant1_up,
                        } => {
                            let any_declared_name_matches_hovered: bool =
                                (origin_module_declaration_variant0_name_node
                                    .as_ref()
                                    .is_some_and(|name_node| name_node.value.as_ref() == hovered_name))
                                    || (origin_module_declaration_variant1_up.iter().any(
                                        |variant| {
                                            variant.name.as_ref().is_some_and(|name_node| {
                                                name_node.value.as_ref() == hovered_name
                                            })
                                        },
                                    ));
                            if any_declared_name_matches_hovered {
                                Some(format!(
                                    "variant in\n{}",
                                    &present_choice_type_declaration_info_markdown(
                                        &origin_module_origin_lookup,
                                        hovered_module_origin,
                                        &hovered_project_module_state.module.syntax.comments,
                                        origin_module_declaration_node.range,
                                        origin_module_declaration_name
                                            .as_ref()
                                            .map(gren_syntax_node_unbox),
                                        origin_module_declaration
                                            .documentation
                                            .as_ref()
                                            .map(|node| node.value.as_ref()),
                                        origin_module_declaration_parameters,
                                        origin_module_declaration_variant0_name_node
                                            .as_ref()
                                            .map(gren_syntax_node_unbox),
                                        origin_module_declaration_variant0_maybe_value
                                            .as_ref()
                                            .map(gren_syntax_node_as_ref),
                                        origin_module_declaration_variant1_up,
                                    )
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator {
                            direction: maybe_origin_module_declaration_direction,
                            precedence: maybe_origin_module_declaration_precedence,
                            operator: maybe_origin_module_declaration_operator,
                            equals_key_symbol_range: _,
                            function: maybe_origin_module_declaration_function,
                        } => {
                            if maybe_origin_module_declaration_operator
                                .as_ref()
                                .is_some_and(|operator_node| operator_node.value == hovered_name)
                            {
                                let maybe_origin_operator_function_declaration =
                                    maybe_origin_module_declaration_function.as_ref().and_then(
                                        |origin_module_declaration_function_node| {
                                            origin_module_state.syntax.declarations.iter().find_map(
                                                |origin_module_potential_function_declaration_or_err| {
                                                    let origin_module_potential_function_declaration = origin_module_potential_function_declaration_or_err.as_ref().ok()?;
                                                    let origin_module_potential_function_declaration_node = origin_module_potential_function_declaration.declaration.as_ref()?;
                                                    match &origin_module_potential_function_declaration_node.value {
                                                        GrenSyntaxDeclaration::Variable {
                                                            start_name: origin_module_declaration_name,
                                                            signature: origin_module_declaration_signature,
                                                            ..
                                                        } if origin_module_declaration_name.value
                                                            == origin_module_declaration_function_node.value => {
                                                            Some((
                                                                origin_module_declaration_signature.as_ref(),
                                                                origin_module_potential_function_declaration
                                                                    .documentation
                                                                    .as_ref()
                                                                    .map(|node| node.value.as_ref()),
                                                            ))
                                                        }
                                                        _ => None,
                                                    }
                                                })
                                            },
                                        );
                                Some(present_operator_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    maybe_origin_module_declaration_operator
                                        .as_ref()
                                        .map(|node| node.value),
                                    maybe_origin_operator_function_declaration,
                                    origin_module_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    maybe_origin_module_declaration_direction
                                        .map(|node| node.value),
                                    maybe_origin_module_declaration_precedence
                                        .map(|node| node.value),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Port {
                            name: maybe_origin_module_declaration_name,
                            colon_key_symbol_range: _,
                            type_,
                        } => {
                            if let Some(origin_module_declaration_name_node) = maybe_origin_module_declaration_name &&
                                origin_module_declaration_name_node.value.as_ref() == hovered_name {
                                Some(present_port_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(origin_module_declaration_name_node)),
                                    origin_module_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias { .. } => None,
                        GrenSyntaxDeclaration::Variable {
                            start_name: origin_module_declaration_name_node,
                            signature: origin_module_declaration_maybe_signature,
                            parameters: _,
                            equals_key_symbol_range: _,
                            result: _,
                        } => {
                            if origin_module_declaration_name_node.value.as_ref()== hovered_name {
                                Some(present_variable_declaration_info_markdown(
                                    &origin_module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    gren_syntax_node_unbox(origin_module_declaration_name_node),
                                    origin_module_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    origin_module_declaration_maybe_signature
                                        .as_ref()
                                        .and_then(|signature|
                                            signature
                                                .type_
                                                .as_ref()
                                        ).map(gren_syntax_node_as_ref),
                                ))
                            } else {
                                None
                            }
                        }
                    }
                })?;
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: origin_declaration_info_markdown,
                }),
                range: Some(hovered_symbol_node.range),
            })
        }
        GrenSyntaxSymbol::Type {
            qualification: hovered_qualification,
            name: hovered_name,
        } => {
            let hovered_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    hovered_project_module_state.project,
                    &hovered_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: hovered_qualification,
                    name: hovered_name,
                },
            );
            let (_, origin_module_state) = project_state_get_module_with_name(
                state,
                hovered_project_module_state.project,
                hovered_module_origin,
            )?;
            let module_origin_lookup: ModuleOriginLookup = gren_syntax_module_create_origin_lookup(
                state,
                hovered_project_module_state.project,
                &origin_module_state.syntax,
            );
            let info_markdown: String = origin_module_state.syntax.declarations.iter().find_map(
                |origin_module_declaration_or_err| {
                    let origin_module_declaration =
                        origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node =
                        origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: maybe_origin_module_declaration_name,
                            parameters: origin_module_declaration_parameters,
                            equals_key_symbol_range: _,
                            variant0_name: maybe_origin_module_declaration_variant0_name_node,
                            variant0_value: maybe_origin_module_declaration_variant0_maybe_value,
                            variant1_up: origin_module_declaration_variant1_up,
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_declaration_name
                                && origin_module_declaration_name_node.value.as_ref()
                                    == hovered_name
                            {
                                Some(present_choice_type_declaration_info_markdown(
                                    &module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(
                                        origin_module_declaration_name_node,
                                    )),
                                    origin_module_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    origin_module_declaration_parameters,
                                    maybe_origin_module_declaration_variant0_name_node
                                        .as_ref()
                                        .map(gren_syntax_node_unbox),
                                    maybe_origin_module_declaration_variant0_maybe_value
                                        .as_ref()
                                        .map(gren_syntax_node_as_ref),
                                    origin_module_declaration_variant1_up,
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias {
                            alias_keyword_range: _,
                            name: maybe_origin_module_declaration_name,
                            parameters: origin_module_declaration_parameters,
                            equals_key_symbol_range: _,
                            type_,
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_declaration_name
                                && origin_module_declaration_name_node.value.as_ref()
                                    == hovered_name
                            {
                                Some(present_type_alias_declaration_info_markdown(
                                    &module_origin_lookup,
                                    hovered_module_origin,
                                    &hovered_project_module_state.module.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(
                                        origin_module_declaration_name_node,
                                    )),
                                    origin_module_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                    origin_module_declaration_parameters,
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ))
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator { .. }
                        | GrenSyntaxDeclaration::Port { .. }
                        | GrenSyntaxDeclaration::Variable { .. } => None,
                    }
                },
            )?;
            Some(lsp_types::Hover {
                contents: lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: info_markdown,
                }),
                range: Some(hovered_symbol_node.range),
            })
        }
    }
}

fn local_binding_info_markdown(
    state: &State,
    project_state: &ProjectState,
    module_syntax: &GrenSyntaxModule,
    binding_name: &str,
    binding_origin: LocalBindingOrigin,
) -> String {
    match binding_origin {
        LocalBindingOrigin::PatternVariable(_) => "variable introduced in pattern".to_string(),
        LocalBindingOrigin::PatternRecordField(_) => {
            "variable bound to a field, introduced in a pattern".to_string()
        }
        LocalBindingOrigin::LetDeclaredVariable {
            signature: maybe_signature,
            start_name_range,
        } => let_declaration_info_markdown(
            state,
            project_state,
            module_syntax,
            GrenSyntaxNode {
                value: binding_name,
                range: start_name_range,
            },
            maybe_signature
                .and_then(|signature| signature.type_.as_ref())
                .map(gren_syntax_node_as_ref),
        ),
    }
}
fn let_declaration_info_markdown(
    state: &State,
    project_state: &ProjectState,
    module_syntax: &GrenSyntaxModule,
    start_name_node: GrenSyntaxNode<&str>,
    maybe_signature_type: Option<GrenSyntaxNode<&GrenSyntaxType>>,
) -> String {
    match maybe_signature_type {
        None => {
            format!("```gren\nlet {}\n```\n", start_name_node.value)
        }
        Some(hovered_local_binding_signature) => {
            let signature_type_internal_comments = gren_syntax_comments_in_range(
                &module_syntax.comments,
                hovered_local_binding_signature.range,
            );
            format!(
                "```gren\nlet {} :{}{}\n```\n",
                start_name_node.value,
                match gren_syntax_range_line_span(
                    lsp_types::Range {
                        start: start_name_node.range.end,
                        end: hovered_local_binding_signature.range.end
                    },
                    signature_type_internal_comments
                ) {
                    LineSpan::Single => " ",
                    LineSpan::Multiple => "\n    ",
                },
                &gren_syntax_type_to_string(
                    &gren_syntax_module_create_origin_lookup(state, project_state, module_syntax),
                    hovered_local_binding_signature,
                    4,
                    signature_type_internal_comments
                )
            )
        }
    }
}

fn respond_to_goto_definition(
    state: &State,
    goto_definition_arguments: lsp_types::GotoDefinitionParams,
) -> Option<lsp_types::GotoDefinitionResponse> {
    let goto_symbol_project_module_state = state_get_project_module_by_lsp_url(
        state,
        &goto_definition_arguments
            .text_document_position_params
            .text_document
            .uri,
    )?;
    let goto_symbol_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &goto_symbol_project_module_state.module.syntax,
            goto_definition_arguments
                .text_document_position_params
                .position,
        )?;
    match goto_symbol_node.value {
        GrenSyntaxSymbol::LetDeclarationName { .. }
        | GrenSyntaxSymbol::ModuleMemberDeclarationName { .. } => {
            // already at definition
            None
        }
        GrenSyntaxSymbol::TypeVariable {
            scope_declaration,
            name: goto_type_variable_name,
        } => {
            match scope_declaration {
                GrenSyntaxDeclaration::ChoiceType {
                    name: _,
                    parameters: origin_type_parameters,
                    equals_key_symbol_range: _,
                    variant0_name: _,
                    variant0_value: _,
                    variant1_up: _,
                } => {
                    let goto_type_variable_name_origin_parameter_node = origin_type_parameters
                        .iter()
                        .find(|origin_choice_type_parameter| {
                            origin_choice_type_parameter.value.as_ref() == goto_type_variable_name
                        })?;
                    Some(lsp_types::GotoDefinitionResponse::Scalar(
                        lsp_types::Location {
                            uri: goto_definition_arguments
                                .text_document_position_params
                                .text_document
                                .uri,
                            range: goto_type_variable_name_origin_parameter_node.range,
                        },
                    ))
                }
                GrenSyntaxDeclaration::TypeAlias {
                    alias_keyword_range: _,
                    name: _,
                    parameters: origin_type_parameters,
                    equals_key_symbol_range: _,
                    type_: _,
                } => {
                    let goto_type_variable_name_origin_parameter_node = origin_type_parameters
                        .iter()
                        .find(|origin_choice_type_parameter| {
                            origin_choice_type_parameter.value.as_ref() == goto_type_variable_name
                        })?;
                    Some(lsp_types::GotoDefinitionResponse::Scalar(
                        lsp_types::Location {
                            uri: goto_definition_arguments
                                .text_document_position_params
                                .text_document
                                .uri,
                            range: goto_type_variable_name_origin_parameter_node.range,
                        },
                    ))
                }
                GrenSyntaxDeclaration::Variable { .. }
                | GrenSyntaxDeclaration::Operator { .. }
                | GrenSyntaxDeclaration::Port { .. } => None,
            }
        }
        GrenSyntaxSymbol::ModuleName(goto_module_name) => {
            if let Some(goto_symbol_module_header) =
                &goto_symbol_project_module_state.module.syntax.header
                && let Some(goto_symbol_module_name_node) = &goto_symbol_module_header.module_name
                && goto_symbol_module_name_node.value.as_ref() == goto_module_name
            {
                return None;
            }
            let (origin_module_file_path, origin_module_state) =
                project_state_get_module_with_name(
                    state,
                    goto_symbol_project_module_state.project,
                    goto_module_name,
                )?;
            let origin_module_file_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_file_path).ok()?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: origin_module_file_url,
                    range: match &origin_module_state.syntax.header {
                        Some(module_header) => match &module_header.module_name {
                            Some(module_name_node) => module_name_node.range,
                            None => match module_header.specific {
                                GrenSyntaxModuleHeaderSpecific::Pure {
                                    module_keyword_range,
                                }
                                | GrenSyntaxModuleHeaderSpecific::Port {
                                    port_keyword_range: _,
                                    module_keyword_range,
                                }
                                | GrenSyntaxModuleHeaderSpecific::Effect {
                                    module_keyword_range,
                                    ..
                                } => module_keyword_range,
                            },
                        },
                        None => lsp_types::Range {
                            start: lsp_types::Position {
                                line: 0,
                                character: 0,
                            },
                            end: lsp_types::Position {
                                line: 1,
                                character: 0,
                            },
                        },
                    },
                },
            ))
        }
        GrenSyntaxSymbol::ImportAlias {
            module_origin: goto_module_name,
            alias_name: _,
        } => {
            let (origin_module_file_path, origin_module_state) =
                project_state_get_module_with_name(
                    state,
                    goto_symbol_project_module_state.project,
                    goto_module_name,
                )?;
            let origin_module_file_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_file_path).ok()?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: origin_module_file_url,
                    range: match &origin_module_state.syntax.header {
                        Some(module_header) => match &module_header.module_name {
                            Some(module_name_node) => module_name_node.range,
                            None => match module_header.specific {
                                GrenSyntaxModuleHeaderSpecific::Pure {
                                    module_keyword_range,
                                }
                                | GrenSyntaxModuleHeaderSpecific::Port {
                                    port_keyword_range: _,
                                    module_keyword_range,
                                }
                                | GrenSyntaxModuleHeaderSpecific::Effect {
                                    module_keyword_range,
                                    ..
                                } => module_keyword_range,
                            },
                        },
                        None => lsp_types::Range {
                            start: lsp_types::Position {
                                line: 0,
                                character: 0,
                            },
                            end: lsp_types::Position {
                                line: 1,
                                character: 0,
                            },
                        },
                    },
                },
            ))
        }
        GrenSyntaxSymbol::ModuleHeaderExpose {
            name: goto_name,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name: goto_name,
            module_documentation: _,
        } => {
            let declaration_name_range: lsp_types::Range = goto_symbol_project_module_state
                .module
                .syntax
                .declarations
                .iter()
                .find_map(|origin_module_declaration_or_err| {
                    let origin_module_declaration =
                        origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node =
                        origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: maybe_origin_module_choice_type_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_choice_type_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator {
                            operator: maybe_origin_module_declaration_operator,
                            function: maybe_origin_module_declaration_function,
                            ..
                        } => {
                            if let Some(origin_module_declaration_operator_node) =
                                maybe_origin_module_declaration_operator
                                && origin_module_declaration_operator_node.value == goto_name
                            {
                                Some(origin_module_declaration_operator_node.range)
                            } else if let Some(origin_module_declaration_function_node) =
                                maybe_origin_module_declaration_function
                                && origin_module_declaration_function_node.value.as_ref()
                                    == goto_name
                            {
                                Some(origin_module_declaration_function_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Port {
                            name: maybe_origin_module_port_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_port_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias {
                            name: maybe_origin_module_declaration_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_declaration_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Variable {
                            start_name: origin_module_declaration_name_node,
                            ..
                        } => {
                            if origin_module_declaration_name_node.value.as_ref() == goto_name {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                    }
                })?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: goto_definition_arguments
                        .text_document_position_params
                        .text_document
                        .uri,
                    range: declaration_name_range,
                },
            ))
        }
        GrenSyntaxSymbol::ImportExpose {
            origin_module: goto_module_origin,
            name: goto_name,
            all_exposes: _,
        } => {
            let (origin_module_file_path, origin_module_state) =
                project_state_get_module_with_name(
                    state,
                    goto_symbol_project_module_state.project,
                    goto_module_origin,
                )?;
            let origin_module_file_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_file_path).ok()?;
            let declaration_name_range: lsp_types::Range = origin_module_state
                .syntax
                .declarations
                .iter()
                .find_map(|origin_module_declaration_or_err| {
                    let origin_module_declaration =
                        origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node =
                        origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: maybe_origin_module_choice_type_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_choice_type_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator {
                            operator: maybe_origin_module_operator,
                            ..
                        } => {
                            if let Some(origin_module_declaration_operator_node) =
                                maybe_origin_module_operator
                                && origin_module_declaration_operator_node.value == goto_name
                            {
                                Some(origin_module_declaration_operator_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Port {
                            name: maybe_origin_module_port_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_port_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias {
                            name: maybe_origin_module_type_alias_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_type_alias_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Variable {
                            start_name: origin_module_declaration_name_node,
                            ..
                        } => {
                            if origin_module_declaration_name_node.value.as_ref() == goto_name {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                    }
                })?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: origin_module_file_url,
                    range: declaration_name_range,
                },
            ))
        }
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification: goto_qualification,
            name: goto_name,
            local_bindings,
        } => {
            if goto_qualification.is_empty()
                && let Some((goto_local_binding_origin, _)) =
                    find_local_binding_scope_expression(&local_bindings, goto_name)
            {
                return Some(lsp_types::GotoDefinitionResponse::Scalar(
                    lsp_types::Location {
                        uri: goto_definition_arguments
                            .text_document_position_params
                            .text_document
                            .uri,
                        range: match goto_local_binding_origin {
                            LocalBindingOrigin::PatternVariable(range)
                            | LocalBindingOrigin::PatternRecordField(range) => range,
                            LocalBindingOrigin::LetDeclaredVariable {
                                signature: _,
                                start_name_range,
                            } => start_name_range,
                        },
                    },
                ));
            }
            let goto_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    goto_symbol_project_module_state.project,
                    &goto_symbol_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: goto_qualification,
                    name: goto_name,
                },
            );
            let (origin_module_file_path, origin_module_state) =
                project_state_get_module_with_name(
                    state,
                    goto_symbol_project_module_state.project,
                    goto_module_origin,
                )?;
            let origin_module_file_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_file_path).ok()?;
            let declaration_name_range: lsp_types::Range = origin_module_state
                .syntax
                .declarations
                .iter()
                .find_map(|origin_module_declaration_or_err| {
                    let origin_module_declaration =
                        origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node =
                        origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            variant0_name: maybe_origin_module_declaration_variant0_name_node,
                            variant1_up: origin_module_declaration_variant1_up,
                            ..
                        } => {
                            if let Some(origin_module_declaration_variant0_name_node) =
                                maybe_origin_module_declaration_variant0_name_node
                                && origin_module_declaration_variant0_name_node.value.as_ref()
                                    == goto_name
                            {
                                Some(origin_module_declaration_variant0_name_node.range)
                            } else {
                                origin_module_declaration_variant1_up
                                    .iter()
                                    .find_map(|variant| {
                                        variant.name.as_ref().and_then(|variant_name_node| {
                                            if variant_name_node.value.as_ref() == goto_name {
                                                Some(variant_name_node.range)
                                            } else {
                                                None
                                            }
                                        })
                                    })
                            }
                        }
                        GrenSyntaxDeclaration::Operator {
                            operator: maybe_origin_module_declaration_operator,
                            function: maybe_origin_module_declaration_function,
                            ..
                        } => {
                            if let Some(origin_module_declaration_operator_node) =
                                maybe_origin_module_declaration_operator
                                && origin_module_declaration_operator_node.value == goto_name
                            {
                                Some(origin_module_declaration_operator_node.range)
                            } else if let Some(origin_module_declaration_function_node) =
                                maybe_origin_module_declaration_function
                                && origin_module_declaration_function_node.value.as_ref()
                                    == goto_name
                            {
                                Some(origin_module_declaration_function_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Port {
                            name: maybe_origin_module_declaration_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_declaration_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::TypeAlias { .. } => None,
                        GrenSyntaxDeclaration::Variable {
                            start_name: origin_module_declaration_name_node,
                            ..
                        } => {
                            if origin_module_declaration_name_node.value.as_ref() == goto_name {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                    }
                })?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: origin_module_file_url,
                    range: declaration_name_range,
                },
            ))
        }
        GrenSyntaxSymbol::Type {
            qualification: goto_qualification,
            name: goto_name,
        } => {
            let goto_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    goto_symbol_project_module_state.project,
                    &goto_symbol_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: goto_qualification,
                    name: goto_name,
                },
            );
            let (origin_module_file_path, origin_module_state) =
                project_state_get_module_with_name(
                    state,
                    goto_symbol_project_module_state.project,
                    goto_module_origin,
                )?;
            let origin_module_file_url: lsp_types::Url =
                lsp_types::Url::from_file_path(origin_module_file_path).ok()?;
            let declaration_name_range: lsp_types::Range = origin_module_state
                .syntax
                .declarations
                .iter()
                .find_map(|origin_module_declaration_or_err| {
                    let origin_module_declaration =
                        origin_module_declaration_or_err.as_ref().ok()?;
                    let origin_module_declaration_node =
                        origin_module_declaration.declaration.as_ref()?;
                    match &origin_module_declaration_node.value {
                        GrenSyntaxDeclaration::ChoiceType {
                            name: maybe_origin_module_declaration_name,
                            ..
                        }
                        | GrenSyntaxDeclaration::TypeAlias {
                            name: maybe_origin_module_declaration_name,
                            ..
                        } => {
                            if let Some(origin_module_declaration_name_node) =
                                maybe_origin_module_declaration_name
                                && origin_module_declaration_name_node.value.as_ref() == goto_name
                            {
                                Some(origin_module_declaration_name_node.range)
                            } else {
                                None
                            }
                        }
                        GrenSyntaxDeclaration::Operator { .. }
                        | GrenSyntaxDeclaration::Port { .. }
                        | GrenSyntaxDeclaration::Variable { .. } => None,
                    }
                })?;
            Some(lsp_types::GotoDefinitionResponse::Scalar(
                lsp_types::Location {
                    uri: origin_module_file_url,
                    range: declaration_name_range,
                },
            ))
        }
    }
}

fn respond_to_prepare_rename(
    state: &State,
    prepare_rename_arguments: &lsp_types::TextDocumentPositionParams,
) -> Option<Result<lsp_types::PrepareRenameResponse, lsp_server::ResponseError>> {
    let project_module_state =
        state_get_project_module_by_lsp_url(state, &prepare_rename_arguments.text_document.uri)?;
    let prepare_rename_symbol_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &project_module_state.module.syntax,
            prepare_rename_arguments.position,
        )?;
    Some(match prepare_rename_symbol_node.value {
        GrenSyntaxSymbol::ImportAlias {
            module_origin: _,
            alias_name,
        } => Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
            range: prepare_rename_symbol_node.range,
            placeholder: alias_name.to_string(),
        }),
        GrenSyntaxSymbol::ModuleName(module_name) => {
            Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
                range: prepare_rename_symbol_node.range,
                placeholder: module_name.to_string(),
            })
        }
        GrenSyntaxSymbol::ModuleHeaderExpose {
            name,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name,
            module_documentation: _,
        }
        | GrenSyntaxSymbol::ImportExpose {
            name,
            origin_module: _,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleMemberDeclarationName {
            name,
            declaration: _,
            documentation: _,
        }
        | GrenSyntaxSymbol::LetDeclarationName {
            name,
            signature_type: _,
            start_name_range: _,
            scope_expression: _,
        }
        | GrenSyntaxSymbol::TypeVariable {
            scope_declaration: _,
            name,
        } => Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
            range: prepare_rename_symbol_node.range,
            placeholder: name.to_string(),
        }),
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification,
            name,
            local_bindings,
        } => {
            if qualification.is_empty()
                && let Some((local_binding_origin, _)) =
                    find_local_binding_scope_expression(&local_bindings, name)
            {
                match local_binding_origin {
                    LocalBindingOrigin::PatternVariable(_)
                    | LocalBindingOrigin::LetDeclaredVariable { .. } => {
                        Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
                            range: prepare_rename_symbol_node.range,
                            placeholder: name.to_string(),
                        })
                    }
                    LocalBindingOrigin::PatternRecordField(_) => Err(lsp_server::ResponseError {
                        code: lsp_server::ErrorCode::RequestFailed as i32,
                        message: "cannot rename a variable that is bound to a field name"
                            .to_string(),
                        data: None,
                    }),
                }
            } else {
                Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
                    range: lsp_types::Range {
                        start: lsp_position_add_characters(
                            prepare_rename_symbol_node.range.end,
                            -(name.len() as i32),
                        ),
                        end: prepare_rename_symbol_node.range.end,
                    },
                    placeholder: name.to_string(),
                })
            }
        }
        GrenSyntaxSymbol::Type {
            qualification: _,
            name,
        } => Ok(lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
            range: lsp_types::Range {
                start: lsp_position_add_characters(
                    prepare_rename_symbol_node.range.end,
                    -(name.len() as i32),
                ),
                end: prepare_rename_symbol_node.range.end,
            },
            placeholder: name.to_string(),
        }),
    })
}

struct ProjectModuleOriginAndState<'a> {
    project_state: &'a ProjectState,
    module_path: &'a std::path::PathBuf,
    module_state: &'a ModuleState,
}

fn state_iter_all_modules<'a>(
    state: &'a State,
) -> impl Iterator<Item = ProjectModuleOriginAndState<'a>> {
    state.projects.values().flat_map(|project_state| {
        project_state
            .modules
            .iter()
            .map(|(module_path, module_state)| ProjectModuleOriginAndState {
                project_state: project_state,
                module_path: module_path,
                module_state: module_state,
            })
    })
}

fn respond_to_rename(
    state: &State,
    rename_arguments: lsp_types::RenameParams,
) -> Option<Vec<lsp_types::TextDocumentEdit>> {
    let to_rename_project_module_state = state_get_project_module_by_lsp_url(
        state,
        &rename_arguments.text_document_position.text_document.uri,
    )?;
    let symbol_to_rename_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &to_rename_project_module_state.module.syntax,
            rename_arguments.text_document_position.position,
        )?;
    Some(match symbol_to_rename_node.value {
        GrenSyntaxSymbol::ImportAlias {
            module_origin: import_alias_to_rename_module_origin,
            alias_name: import_alias_to_rename,
        } => {
            let mut all_uses_of_renamed_import_alias: Vec<lsp_types::Range> = Vec::new();
            gren_syntax_module_uses_of_reference_into(
                &mut all_uses_of_renamed_import_alias,
                state,
                to_rename_project_module_state.project,
                &to_rename_project_module_state.module.syntax,
                GrenSymbolToReference::ImportAlias {
                    module_origin: import_alias_to_rename_module_origin,
                    alias_name: import_alias_to_rename,
                },
            );
            vec![lsp_types::TextDocumentEdit {
                text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                    uri: rename_arguments.text_document_position.text_document.uri,
                    version: None,
                },
                edits: all_uses_of_renamed_import_alias
                    .into_iter()
                    .map(|use_range_of_renamed_module| {
                        lsp_types::OneOf::Left(lsp_types::TextEdit {
                            range: use_range_of_renamed_module,
                            new_text: rename_arguments.new_name.clone(),
                        })
                    })
                    .collect::<Vec<_>>(),
            }]
        }
        GrenSyntaxSymbol::TypeVariable {
            scope_declaration,
            name: type_variable_to_rename,
        } => {
            let mut all_uses_of_renamed_type_variable: Vec<lsp_types::Range> = Vec::new();
            gren_syntax_declaration_uses_of_reference_into(
                &mut all_uses_of_renamed_type_variable,
                to_rename_project_module_state
                    .module
                    .syntax
                    .header
                    .as_ref()
                    .and_then(|header| header.module_name.as_ref())
                    .map(|node| node.value.as_ref())
                    .unwrap_or(""),
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_rename_project_module_state.project,
                    &to_rename_project_module_state.module.syntax,
                ),
                scope_declaration,
                GrenSymbolToReference::TypeVariable(type_variable_to_rename),
            );
            vec![lsp_types::TextDocumentEdit {
                text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                    uri: rename_arguments.text_document_position.text_document.uri,
                    version: None,
                },
                edits: all_uses_of_renamed_type_variable
                    .into_iter()
                    .map(|use_range_of_renamed_module| {
                        lsp_types::OneOf::Left(lsp_types::TextEdit {
                            range: use_range_of_renamed_module,
                            new_text: rename_arguments.new_name.clone(),
                        })
                    })
                    .collect::<Vec<_>>(),
            }]
        }
        GrenSyntaxSymbol::ModuleName(module_name_to_rename) => state
            .projects
            .values()
            .flat_map(|project| project.modules.iter())
            .filter_map(|(gren_module_file_path, gren_module_state)| {
                let gren_module_uri = lsp_types::Url::from_file_path(gren_module_file_path).ok()?;
                let mut all_uses_of_renamed_module_name: Vec<lsp_types::Range> = Vec::new();
                gren_syntax_module_uses_of_reference_into(
                    &mut all_uses_of_renamed_module_name,
                    state,
                    to_rename_project_module_state.project,
                    &gren_module_state.syntax,
                    GrenSymbolToReference::ModuleName(module_name_to_rename),
                );
                Some(lsp_types::TextDocumentEdit {
                    text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                        uri: gren_module_uri,
                        version: None,
                    },
                    edits: all_uses_of_renamed_module_name
                        .into_iter()
                        .map(|use_range_of_renamed_module| {
                            lsp_types::OneOf::Left(lsp_types::TextEdit {
                                range: use_range_of_renamed_module,
                                new_text: rename_arguments.new_name.clone(),
                            })
                        })
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
        GrenSyntaxSymbol::ModuleMemberDeclarationName {
            name: to_rename_declaration_name,
            documentation: _,
            declaration: _,
        }
        | GrenSyntaxSymbol::ModuleHeaderExpose {
            name: to_rename_declaration_name,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name: to_rename_declaration_name,
            module_documentation: _,
        } => {
            let to_rename_module_origin: &str = to_rename_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let gren_declared_symbol_to_rename: GrenSymbolToReference =
                if to_rename_declaration_name.starts_with(char::is_uppercase) {
                    GrenSymbolToReference::Type {
                        module_origin: to_rename_module_origin,
                        name: to_rename_declaration_name,
                        including_declaration_name: true,
                    }
                } else {
                    GrenSymbolToReference::VariableOrVariant {
                        module_origin: to_rename_module_origin,
                        name: to_rename_declaration_name,
                        including_declaration_name: true,
                    }
                };
            state_iter_all_modules(state)
                .filter_map(move |project_module| {
                    let mut all_uses_of_at_docs_module_member: Vec<lsp_types::Range> = Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_of_at_docs_module_member,
                        state,
                        project_module.project_state,
                        &project_module.module_state.syntax,
                        gren_declared_symbol_to_rename,
                    );
                    let gren_module_uri: lsp_types::Url =
                        lsp_types::Url::from_file_path(project_module.module_path).ok()?;
                    Some(lsp_types::TextDocumentEdit {
                        text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                            uri: gren_module_uri,
                            version: None,
                        },
                        edits: all_uses_of_at_docs_module_member
                            .into_iter()
                            .map(|use_range_of_renamed_module| {
                                lsp_types::OneOf::Left(lsp_types::TextEdit {
                                    range: use_range_of_renamed_module,
                                    new_text: rename_arguments.new_name.clone(),
                                })
                            })
                            .collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::ImportExpose {
            origin_module: to_rename_import_expose_origin_module,
            name: to_rename_import_expose_name,
            all_exposes: _,
        } => {
            let gren_declared_symbol_to_rename: GrenSymbolToReference =
                if to_rename_import_expose_name.starts_with(char::is_uppercase) {
                    GrenSymbolToReference::Type {
                        module_origin: to_rename_import_expose_origin_module,
                        name: to_rename_import_expose_name,
                        including_declaration_name: true,
                    }
                } else {
                    GrenSymbolToReference::VariableOrVariant {
                        module_origin: to_rename_import_expose_origin_module,
                        name: to_rename_import_expose_name,
                        including_declaration_name: true,
                    }
                };
            state_iter_all_modules(state)
                .filter_map(move |project_module| {
                    let mut all_uses_import_exposed_member: Vec<lsp_types::Range> = Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_import_exposed_member,
                        state,
                        project_module.project_state,
                        &project_module.module_state.syntax,
                        gren_declared_symbol_to_rename,
                    );
                    let gren_module_uri: lsp_types::Url =
                        lsp_types::Url::from_file_path(project_module.module_path).ok()?;
                    Some(lsp_types::TextDocumentEdit {
                        text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                            uri: gren_module_uri,
                            version: None,
                        },
                        edits: all_uses_import_exposed_member
                            .into_iter()
                            .map(|use_range_of_renamed_module| {
                                lsp_types::OneOf::Left(lsp_types::TextEdit {
                                    range: use_range_of_renamed_module,
                                    new_text: rename_arguments.new_name.clone(),
                                })
                            })
                            .collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::LetDeclarationName {
            name: to_rename_name,
            start_name_range,
            signature_type: _,
            scope_expression,
        } => {
            let mut all_uses_of_let_declaration_to_rename: Vec<lsp_types::Range> = Vec::new();
            gren_syntax_expression_uses_of_reference_into(
                &mut all_uses_of_let_declaration_to_rename,
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_rename_project_module_state.project,
                    &to_rename_project_module_state.module.syntax,
                ),
                &[GrenLocalBinding {
                    name: to_rename_name,
                    origin: LocalBindingOrigin::LetDeclaredVariable {
                        signature: None, // irrelevant fir finding uses
                        start_name_range: start_name_range,
                    },
                }],
                scope_expression,
                GrenSymbolToReference::LocalBinding {
                    name: to_rename_name,
                    including_let_declaration_name: true,
                },
            );
            vec![lsp_types::TextDocumentEdit {
                text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                    uri: rename_arguments.text_document_position.text_document.uri,
                    version: None,
                },
                edits: all_uses_of_let_declaration_to_rename
                    .into_iter()
                    .map(|use_range_of_renamed_module| {
                        lsp_types::OneOf::Left(lsp_types::TextEdit {
                            range: use_range_of_renamed_module,
                            new_text: rename_arguments.new_name.clone(),
                        })
                    })
                    .collect::<Vec<_>>(),
            }]
        }
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification: to_rename_qualification,
            name: to_rename_name,
            local_bindings,
        } => {
            if to_rename_qualification.is_empty()
                && let Some((
                    to_rename_local_binding_origin,
                    local_binding_to_rename_scope_expression,
                )) = find_local_binding_scope_expression(&local_bindings, to_rename_name)
            {
                let mut all_uses_of_local_binding_to_rename: Vec<lsp_types::Range> = Vec::new();
                gren_syntax_expression_uses_of_reference_into(
                    &mut all_uses_of_local_binding_to_rename,
                    &gren_syntax_module_create_origin_lookup(
                        state,
                        to_rename_project_module_state.project,
                        &to_rename_project_module_state.module.syntax,
                    ),
                    &[GrenLocalBinding {
                        name: to_rename_name,
                        origin: to_rename_local_binding_origin,
                    }],
                    local_binding_to_rename_scope_expression,
                    GrenSymbolToReference::LocalBinding {
                        name: to_rename_name,
                        including_let_declaration_name: true,
                    },
                );
                match to_rename_local_binding_origin {
                    LocalBindingOrigin::PatternVariable(range) => {
                        all_uses_of_local_binding_to_rename.push(range);
                    }
                    LocalBindingOrigin::PatternRecordField(_) => {
                        // should never have been prepared for rename
                    }
                    LocalBindingOrigin::LetDeclaredVariable { .. } => {
                        // already included in scope expression
                    }
                }
                vec![lsp_types::TextDocumentEdit {
                    text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                        uri: rename_arguments.text_document_position.text_document.uri,
                        version: None,
                    },
                    edits: all_uses_of_local_binding_to_rename
                        .into_iter()
                        .map(|use_range_of_renamed_module| {
                            lsp_types::OneOf::Left(lsp_types::TextEdit {
                                range: use_range_of_renamed_module,
                                new_text: rename_arguments.new_name.clone(),
                            })
                        })
                        .collect::<Vec<_>>(),
                }]
            } else {
                let to_rename_module_origin: &str = look_up_origin_module(
                    &gren_syntax_module_create_origin_lookup(
                        state,
                        to_rename_project_module_state.project,
                        &to_rename_project_module_state.module.syntax,
                    ),
                    GrenQualified {
                        qualification: to_rename_qualification,
                        name: to_rename_name,
                    },
                );
                let symbol_to_find: GrenSymbolToReference =
                    GrenSymbolToReference::VariableOrVariant {
                        module_origin: to_rename_module_origin,
                        name: to_rename_name,
                        including_declaration_name: true,
                    };
                state_iter_all_modules(state)
                    .filter_map(|project_module| {
                        let mut all_uses_of_renamed_reference: Vec<lsp_types::Range> = Vec::new();
                        gren_syntax_module_uses_of_reference_into(
                            &mut all_uses_of_renamed_reference,
                            state,
                            project_module.project_state,
                            &project_module.module_state.syntax,
                            symbol_to_find,
                        );
                        let gren_module_uri: lsp_types::Url =
                            lsp_types::Url::from_file_path(project_module.module_path).ok()?;
                        Some(lsp_types::TextDocumentEdit {
                            text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                                uri: gren_module_uri,
                                version: None,
                            },
                            edits: all_uses_of_renamed_reference
                                .into_iter()
                                .map(|use_range_of_renamed_module| {
                                    lsp_types::OneOf::Left(lsp_types::TextEdit {
                                        range: use_range_of_renamed_module,
                                        new_text: rename_arguments.new_name.clone(),
                                    })
                                })
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>()
            }
        }
        GrenSyntaxSymbol::Type {
            qualification: to_rename_qualification,
            name: type_name_to_rename,
        } => {
            let to_rename_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_rename_project_module_state.project,
                    &to_rename_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: to_rename_qualification,
                    name: type_name_to_rename,
                },
            );
            let gren_declared_symbol_to_rename: GrenSymbolToReference =
                GrenSymbolToReference::Type {
                    module_origin: to_rename_module_origin,
                    name: type_name_to_rename,
                    including_declaration_name: true,
                };
            state_iter_all_modules(state)
                .filter_map(|project_module| {
                    let mut all_uses_of_renamed_type: Vec<lsp_types::Range> = Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_of_renamed_type,
                        state,
                        project_module.project_state,
                        &project_module.module_state.syntax,
                        gren_declared_symbol_to_rename,
                    );
                    let gren_module_uri: lsp_types::Url =
                        lsp_types::Url::from_file_path(project_module.module_path).ok()?;
                    Some(lsp_types::TextDocumentEdit {
                        text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                            uri: gren_module_uri,
                            version: None,
                        },
                        edits: all_uses_of_renamed_type
                            .into_iter()
                            .map(|use_range_of_renamed_module| {
                                lsp_types::OneOf::Left(lsp_types::TextEdit {
                                    range: use_range_of_renamed_module,
                                    new_text: rename_arguments.new_name.clone(),
                                })
                            })
                            .collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>()
        }
    })
}
fn respond_to_references(
    state: &State,
    references_arguments: lsp_types::ReferenceParams,
) -> Option<Vec<lsp_types::Location>> {
    let to_find_project_module_state = state_get_project_module_by_lsp_url(
        state,
        &references_arguments
            .text_document_position
            .text_document
            .uri,
    )?;
    let symbol_to_find_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &to_find_project_module_state.module.syntax,
            references_arguments.text_document_position.position,
        )?;
    Some(match symbol_to_find_node.value {
        GrenSyntaxSymbol::ImportAlias {
            module_origin: import_alias_to_find_module_origin,
            alias_name: import_alias_to_find,
        } => {
            let mut all_uses_of_found_import_alias: Vec<lsp_types::Range> =
                if references_arguments.context.include_declaration {
                    vec![symbol_to_find_node.range] // the alias on the import itself
                } else {
                    Vec::new()
                };
            let symbol_to_find: GrenSymbolToReference = GrenSymbolToReference::ImportAlias {
                module_origin: import_alias_to_find_module_origin,
                alias_name: import_alias_to_find,
            };
            let module_origin_lookup: ModuleOriginLookup = gren_syntax_module_create_origin_lookup(
                state,
                to_find_project_module_state.project,
                &to_find_project_module_state.module.syntax,
            );
            let to_find_module_name: &str = to_find_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            for documented_declaration in to_find_project_module_state
                .module
                .syntax
                .declarations
                .iter()
                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
            {
                if let Some(declaration_node) = &documented_declaration.declaration {
                    gren_syntax_declaration_uses_of_reference_into(
                        &mut all_uses_of_found_import_alias,
                        to_find_module_name,
                        &module_origin_lookup,
                        &declaration_node.value,
                        symbol_to_find,
                    );
                }
            }
            all_uses_of_found_import_alias
                .into_iter()
                .map(|use_range_of_found_module| lsp_types::Location {
                    uri: references_arguments
                        .text_document_position
                        .text_document
                        .uri
                        .clone(),
                    range: use_range_of_found_module,
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::TypeVariable {
            scope_declaration,
            name: type_variable_to_find,
        } => {
            let mut all_uses_of_found_type_variable: Vec<lsp_types::Range> = Vec::new();
            gren_syntax_declaration_uses_of_reference_into(
                &mut all_uses_of_found_type_variable,
                to_find_project_module_state
                    .module
                    .syntax
                    .header
                    .as_ref()
                    .and_then(|header| header.module_name.as_ref())
                    .map(|node| node.value.as_ref())
                    .unwrap_or(""),
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_find_project_module_state.project,
                    &to_find_project_module_state.module.syntax,
                ),
                scope_declaration,
                GrenSymbolToReference::TypeVariable(type_variable_to_find),
            );
            all_uses_of_found_type_variable
                .into_iter()
                .map(|use_range_of_found_module| lsp_types::Location {
                    uri: references_arguments
                        .text_document_position
                        .text_document
                        .uri
                        .clone(),
                    range: use_range_of_found_module,
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::ModuleName(module_name_to_find) => to_find_project_module_state
            .project
            .modules
            .iter()
            .filter(|(_, project_module)| {
                if references_arguments.context.include_declaration
                    && let Some(project_module_header) = project_module.syntax.header.as_ref()
                    && let Some(project_module_name_node) =
                        project_module_header.module_name.as_ref()
                {
                    project_module_name_node.value.as_ref() != module_name_to_find
                } else {
                    true
                }
            })
            .flat_map(|(gren_module_file_path, gren_module_state)| {
                let mut all_uses_of_found_module_name: Vec<lsp_types::Range> = Vec::new();
                gren_syntax_module_uses_of_reference_into(
                    &mut all_uses_of_found_module_name,
                    state,
                    to_find_project_module_state.project,
                    &gren_module_state.syntax,
                    GrenSymbolToReference::ModuleName(module_name_to_find),
                );
                lsp_types::Url::from_file_path(gren_module_file_path)
                    .ok()
                    .map(|gren_module_uri| {
                        all_uses_of_found_module_name.into_iter().map(
                            move |use_range_of_found_module| lsp_types::Location {
                                uri: gren_module_uri.clone(),
                                range: use_range_of_found_module,
                            },
                        )
                    })
                    .into_iter()
                    .flatten()
            })
            .collect::<Vec<_>>(),
        GrenSyntaxSymbol::ModuleHeaderExpose {
            name: to_find_name,
            all_exposes: _,
        }
        | GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name: to_find_name,
            module_documentation: _,
        } => {
            let to_find_module_origin: &str = to_find_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let gren_declared_symbol_to_find: GrenSymbolToReference = if to_find_name
                .starts_with(char::is_uppercase)
            {
                GrenSymbolToReference::Type {
                    module_origin: to_find_module_origin,
                    name: to_find_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            } else {
                GrenSymbolToReference::VariableOrVariant {
                    module_origin: to_find_module_origin,
                    name: to_find_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            };
            to_find_project_module_state
                .project
                .modules
                .iter()
                .flat_map(move |(project_module_path, project_module_state)| {
                    lsp_types::Url::from_file_path(project_module_path)
                        .ok()
                        .map(|gren_module_uri| {
                            let mut all_uses_of_found_at_docs_module_member: Vec<lsp_types::Range> =
                                Vec::new();
                            gren_syntax_module_uses_of_reference_into(
                                &mut all_uses_of_found_at_docs_module_member,
                                state,
                                to_find_project_module_state.project,
                                &project_module_state.syntax,
                                gren_declared_symbol_to_find,
                            );
                            all_uses_of_found_at_docs_module_member.into_iter().map(
                                move |use_range_of_found_module| lsp_types::Location {
                                    uri: gren_module_uri.clone(),
                                    range: use_range_of_found_module,
                                },
                            )
                        })
                        .into_iter()
                        .flatten()
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::ModuleMemberDeclarationName {
            name: to_find_name,
            documentation: _,
            declaration: _,
        } => {
            let to_find_module_origin: &str = to_find_project_module_state
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let gren_declared_symbol_to_find: GrenSymbolToReference = if to_find_name
                .starts_with(char::is_uppercase)
            {
                GrenSymbolToReference::Type {
                    module_origin: to_find_module_origin,
                    name: to_find_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            } else {
                GrenSymbolToReference::VariableOrVariant {
                    module_origin: to_find_module_origin,
                    name: to_find_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            };
            to_find_project_module_state
                .project
                .modules
                .iter()
                .flat_map(move |(project_module_path, project_module_state)| {
                    let mut all_uses_of_found_module_member: Vec<lsp_types::Range> = Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_of_found_module_member,
                        state,
                        to_find_project_module_state.project,
                        &project_module_state.syntax,
                        gren_declared_symbol_to_find,
                    );
                    lsp_types::Url::from_file_path(project_module_path)
                        .ok()
                        .map(|gren_module_uri| {
                            all_uses_of_found_module_member.into_iter().map(
                                move |use_range_of_found_module| lsp_types::Location {
                                    uri: gren_module_uri.clone(),
                                    range: use_range_of_found_module,
                                },
                            )
                        })
                        .into_iter()
                        .flatten()
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::ImportExpose {
            origin_module: to_find_import_expose_origin_module,
            name: to_find_import_expose_name,
            all_exposes: _,
        } => {
            let gren_declared_symbol_to_find: GrenSymbolToReference = if to_find_import_expose_name
                .starts_with(char::is_uppercase)
            {
                GrenSymbolToReference::Type {
                    module_origin: to_find_import_expose_origin_module,
                    name: to_find_import_expose_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            } else {
                GrenSymbolToReference::VariableOrVariant {
                    module_origin: to_find_import_expose_origin_module,
                    name: to_find_import_expose_name,
                    including_declaration_name: references_arguments.context.include_declaration,
                }
            };
            to_find_project_module_state
                .project
                .modules
                .iter()
                .flat_map(|(project_module_path, project_module_state)| {
                    let mut all_uses_of_found_import_exposed_member: Vec<lsp_types::Range> =
                        Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_of_found_import_exposed_member,
                        state,
                        to_find_project_module_state.project,
                        &project_module_state.syntax,
                        gren_declared_symbol_to_find,
                    );
                    lsp_types::Url::from_file_path(project_module_path)
                        .ok()
                        .map(|gren_module_uri| {
                            all_uses_of_found_import_exposed_member.into_iter().map(
                                move |use_range_of_found_module| lsp_types::Location {
                                    uri: gren_module_uri.clone(),
                                    range: use_range_of_found_module,
                                },
                            )
                        })
                        .into_iter()
                        .flatten()
                })
                .chain(if references_arguments.context.include_declaration {
                    Some(lsp_types::Location {
                        uri: references_arguments
                            .text_document_position
                            .text_document
                            .uri,
                        range: symbol_to_find_node.range,
                    })
                } else {
                    None
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::LetDeclarationName {
            name: to_find_name,
            start_name_range,
            signature_type: _,
            scope_expression,
        } => {
            let mut all_uses_of_found_let_declaration: Vec<lsp_types::Range> = Vec::new();
            gren_syntax_expression_uses_of_reference_into(
                &mut all_uses_of_found_let_declaration,
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_find_project_module_state.project,
                    &to_find_project_module_state.module.syntax,
                ),
                &[GrenLocalBinding {
                    name: to_find_name,
                    origin: LocalBindingOrigin::LetDeclaredVariable {
                        signature: None, // irrelevant for finding uses
                        start_name_range: start_name_range,
                    },
                }],
                scope_expression,
                GrenSymbolToReference::LocalBinding {
                    name: to_find_name,
                    including_let_declaration_name: references_arguments
                        .context
                        .include_declaration,
                },
            );
            all_uses_of_found_let_declaration
                .into_iter()
                .map(|use_range_of_found_module| lsp_types::Location {
                    uri: references_arguments
                        .text_document_position
                        .text_document
                        .uri
                        .clone(),
                    range: use_range_of_found_module,
                })
                .collect::<Vec<_>>()
        }
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification: to_find_qualification,
            name: to_find_name,
            local_bindings,
        } => {
            if to_find_qualification.is_empty()
                && let Some((to_find_local_binding_origin, local_binding_to_find_scope_expression)) =
                    find_local_binding_scope_expression(&local_bindings, to_find_name)
            {
                let mut all_uses_of_found_local_binding: Vec<lsp_types::Range> = Vec::new();
                gren_syntax_expression_uses_of_reference_into(
                    &mut all_uses_of_found_local_binding,
                    &gren_syntax_module_create_origin_lookup(
                        state,
                        to_find_project_module_state.project,
                        &to_find_project_module_state.module.syntax,
                    ),
                    &[GrenLocalBinding {
                        name: to_find_name,
                        origin: to_find_local_binding_origin,
                    }],
                    local_binding_to_find_scope_expression,
                    GrenSymbolToReference::LocalBinding {
                        name: to_find_name,
                        including_let_declaration_name: references_arguments
                            .context
                            .include_declaration,
                    },
                );
                if references_arguments.context.include_declaration {
                    match to_find_local_binding_origin {
                        LocalBindingOrigin::PatternVariable(range) => {
                            all_uses_of_found_local_binding.push(range);
                        }
                        LocalBindingOrigin::PatternRecordField(range) => {
                            all_uses_of_found_local_binding.push(range);
                        }
                        LocalBindingOrigin::LetDeclaredVariable { .. } => {
                            // already included in scope
                        }
                    }
                }
                all_uses_of_found_local_binding
                    .into_iter()
                    .map(|use_range_of_found_module| lsp_types::Location {
                        uri: references_arguments
                            .text_document_position
                            .text_document
                            .uri
                            .clone(),
                        range: use_range_of_found_module,
                    })
                    .collect::<Vec<_>>()
            } else {
                let to_find_module_origin: &str = look_up_origin_module(
                    &gren_syntax_module_create_origin_lookup(
                        state,
                        to_find_project_module_state.project,
                        &to_find_project_module_state.module.syntax,
                    ),
                    GrenQualified {
                        qualification: to_find_qualification,
                        name: to_find_name,
                    },
                );
                let symbol_to_find: GrenSymbolToReference =
                    GrenSymbolToReference::VariableOrVariant {
                        module_origin: to_find_module_origin,
                        name: to_find_name,
                        including_declaration_name: references_arguments
                            .context
                            .include_declaration,
                    };
                to_find_project_module_state
                    .project
                    .modules
                    .iter()
                    .flat_map(|(project_module_path, project_module_state)| {
                        let mut all_uses_of_found_reference: Vec<lsp_types::Range> = Vec::new();
                        gren_syntax_module_uses_of_reference_into(
                            &mut all_uses_of_found_reference,
                            state,
                            to_find_project_module_state.project,
                            &project_module_state.syntax,
                            symbol_to_find,
                        );
                        lsp_types::Url::from_file_path(project_module_path)
                            .ok()
                            .map(|gren_module_uri| {
                                all_uses_of_found_reference.into_iter().map(
                                    move |use_range_of_found_module| lsp_types::Location {
                                        uri: gren_module_uri.clone(),
                                        range: use_range_of_found_module,
                                    },
                                )
                            })
                            .into_iter()
                            .flatten()
                    })
                    .collect::<Vec<_>>()
            }
        }
        GrenSyntaxSymbol::Type {
            qualification: to_find_qualification,
            name: type_name_to_find,
        } => {
            let to_find_module_origin: &str = look_up_origin_module(
                &gren_syntax_module_create_origin_lookup(
                    state,
                    to_find_project_module_state.project,
                    &to_find_project_module_state.module.syntax,
                ),
                GrenQualified {
                    qualification: to_find_qualification,
                    name: type_name_to_find,
                },
            );
            let gren_declared_symbol_to_find: GrenSymbolToReference = GrenSymbolToReference::Type {
                module_origin: to_find_module_origin,
                name: type_name_to_find,
                including_declaration_name: references_arguments.context.include_declaration,
            };
            to_find_project_module_state
                .project
                .modules
                .iter()
                .flat_map(|(project_module_path, project_module_state)| {
                    let mut all_uses_of_found_type: Vec<lsp_types::Range> = Vec::new();
                    gren_syntax_module_uses_of_reference_into(
                        &mut all_uses_of_found_type,
                        state,
                        to_find_project_module_state.project,
                        &project_module_state.syntax,
                        gren_declared_symbol_to_find,
                    );
                    lsp_types::Url::from_file_path(project_module_path)
                        .ok()
                        .map(|gren_module_uri| {
                            all_uses_of_found_type.into_iter().map(
                                move |use_range_of_found_module| lsp_types::Location {
                                    uri: gren_module_uri.clone(),
                                    range: use_range_of_found_module,
                                },
                            )
                        })
                        .into_iter()
                        .flatten()
                })
                .collect::<Vec<_>>()
        }
    })
}

fn respond_to_semantic_tokens_full(
    state: &State,
    semantic_tokens_arguments: &lsp_types::SemanticTokensParams,
) -> Option<lsp_types::SemanticTokensResult> {
    let project_module_state =
        state_get_project_module_by_lsp_url(state, &semantic_tokens_arguments.text_document.uri)?;
    let mut highlighting: Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>> =
        Vec::with_capacity(project_module_state.module.source.len() / 16);
    gren_syntax_highlight_module_into(&mut highlighting, &project_module_state.module.syntax);
    Some(lsp_types::SemanticTokensResult::Tokens(
        lsp_types::SemanticTokens {
            result_id: None,
            data: highlighting
                .into_iter()
                .scan(
                    lsp_types::Position {
                        line: 0,
                        character: 0,
                    },
                    |previous_start_location, segment| {
                        if (segment.range.end.line != segment.range.start.line)
                            || (segment.range.end.character < segment.range.start.character)
                        {
                            eprintln!(
                                "bad highlight token range: must be single-line and positive {:?}",
                                segment.range
                            );
                            return None;
                        }
                        match lsp_position_positive_delta(
                            *previous_start_location,
                            segment.range.start,
                        ) {
                            Err(error) => {
                                eprintln!("bad highlight token order {error}");
                                None
                            }
                            Ok(delta) => {
                                let token = lsp_types::SemanticToken {
                                    delta_line: delta.line,
                                    delta_start: delta.character,
                                    length: segment.range.end.character
                                        - segment.range.start.character,
                                    token_type: semantic_token_type_to_id(
                                        &gren_syntax_highlight_kind_to_lsp_semantic_token_type(
                                            &segment.value,
                                        ),
                                    ),
                                    token_modifiers_bitset: 0_u32,
                                };
                                segment.range.start.clone_into(previous_start_location);
                                Some(token)
                            }
                        }
                    },
                )
                .collect::<Vec<lsp_types::SemanticToken>>(),
        },
    ))
}

const token_types: [lsp_types::SemanticTokenType; 11] = [
    lsp_types::SemanticTokenType::NUMBER,
    lsp_types::SemanticTokenType::STRING,
    lsp_types::SemanticTokenType::NAMESPACE,
    lsp_types::SemanticTokenType::VARIABLE,
    lsp_types::SemanticTokenType::TYPE,
    lsp_types::SemanticTokenType::TYPE_PARAMETER,
    lsp_types::SemanticTokenType::KEYWORD,
    lsp_types::SemanticTokenType::ENUM_MEMBER,
    lsp_types::SemanticTokenType::PROPERTY,
    lsp_types::SemanticTokenType::COMMENT,
    lsp_types::SemanticTokenType::FUNCTION,
];

fn semantic_token_type_to_id(semantic_token: &lsp_types::SemanticTokenType) -> u32 {
    token_types
        .iter()
        .enumerate()
        .find_map(|(i, token)| {
            if token == semantic_token {
                Some(i as u32)
            } else {
                None
            }
        })
        .unwrap_or(0_u32)
}

fn present_variable_declaration_info_markdown(
    module_origin_lookup: &ModuleOriginLookup,
    module_origin: &str,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    start_name_node: GrenSyntaxNode<&str>,
    maybe_documentation: Option<&str>,
    maybe_signature_type: Option<GrenSyntaxNode<&GrenSyntaxType>>,
) -> String {
    let description: String = match maybe_signature_type {
        Some(signature_type_node) => {
            let type_internal_comments =
                gren_syntax_comments_in_range(comments, signature_type_node.range);
            format!(
                "```gren\n{}.{} :{}{}\n```\n",
                module_origin,
                start_name_node.value,
                match gren_syntax_range_line_span(
                    lsp_types::Range {
                        start: start_name_node.range.end,
                        end: signature_type_node.range.start
                    },
                    type_internal_comments
                ) {
                    LineSpan::Single => " ",
                    LineSpan::Multiple => "\n    ",
                },
                &gren_syntax_type_to_string(
                    module_origin_lookup,
                    signature_type_node,
                    4,
                    type_internal_comments
                )
            )
        }
        None => format!(
            "```gren\n{}.{}\n```\n",
            &module_origin, &start_name_node.value
        ),
    };
    match maybe_documentation {
        None => description,
        Some(documentation) => {
            description + "-----\n" + &documentation_comment_to_markdown(documentation)
        }
    }
}
fn present_port_declaration_info_markdown(
    module_origin_lookup: &ModuleOriginLookup,
    module_origin: &str,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    maybe_documentation: Option<&str>,
    maybe_type: Option<GrenSyntaxNode<&GrenSyntaxType>>,
) -> String {
    let mut declaration_as_string: String = String::new();
    let maybe_fully_qualified_name: Option<GrenSyntaxNode<String>> = maybe_name
        .map(|name_node| gren_syntax_node_map(name_node, |name| format!("{module_origin}.{name}")));
    gren_syntax_port_declaration_into(
        &mut declaration_as_string,
        comments,
        |qualified| look_up_origin_module(module_origin_lookup, qualified),
        declaration_range,
        maybe_fully_qualified_name
            .as_ref()
            .map(|name_node| gren_syntax_node_as_ref_map(name_node, String::as_str)),
        maybe_type,
    );
    let description: String = format!("```gren\n{}\n```\n", declaration_as_string);
    match maybe_documentation {
        None => description,
        Some(documentation) => {
            description + "-----\n" + &documentation_comment_to_markdown(documentation)
        }
    }
}
fn present_type_alias_declaration_info_markdown(
    module_origin_lookup: &ModuleOriginLookup,
    module_origin: &str,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    maybe_documentation: Option<&str>,
    parameters: &[GrenSyntaxNode<Box<str>>],
    maybe_type: Option<GrenSyntaxNode<&GrenSyntaxType>>,
) -> String {
    let mut declaration_as_string: String = String::new();
    let maybe_fully_qualified_name: Option<GrenSyntaxNode<String>> = maybe_name
        .map(|name_node| gren_syntax_node_map(name_node, |name| format!("{module_origin}.{name}")));
    gren_syntax_type_alias_declaration_into(
        &mut declaration_as_string,
        gren_syntax_comments_in_range(comments, declaration_range),
        |qualified| look_up_origin_module(module_origin_lookup, qualified),
        declaration_range,
        maybe_fully_qualified_name
            .as_ref()
            .map(|name_node| gren_syntax_node_as_ref_map(name_node, String::as_str)),
        parameters,
        maybe_type,
    );
    let description = format!("```gren\n{}\n```\n", declaration_as_string);
    match maybe_documentation {
        None => description,
        Some(documentation) => {
            description + "-----\n" + &documentation_comment_to_markdown(documentation)
        }
    }
}
fn present_choice_type_declaration_info_markdown(
    module_origin_lookup: &ModuleOriginLookup,
    module_origin: &str,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    maybe_documentation: Option<&str>,
    parameters: &[GrenSyntaxNode<Box<str>>],
    variant0_name: Option<GrenSyntaxNode<&str>>,
    variant0_maybe_value: Option<GrenSyntaxNode<&GrenSyntaxType>>,
    variant1_up: &[GrenSyntaxChoiceTypeDeclarationTailingVariant],
) -> String {
    let mut declaration_string: String = String::new();
    let maybe_fully_qualified_name: Option<GrenSyntaxNode<String>> = maybe_name
        .map(|name_node| gren_syntax_node_map(name_node, |name| format!("{module_origin}.{name}")));
    gren_syntax_choice_type_declaration_into(
        &mut declaration_string,
        gren_syntax_comments_in_range(comments, declaration_range),
        |qualified| look_up_origin_module(module_origin_lookup, qualified),
        declaration_range,
        maybe_fully_qualified_name
            .as_ref()
            .map(|name_node| gren_syntax_node_as_ref_map(name_node, String::as_str)),
        parameters,
        variant0_name,
        variant0_maybe_value,
        variant1_up,
    );
    let description: String = format!("```gren\n{}\n```\n", declaration_string);
    match maybe_documentation {
        None => description,
        Some(documentation) => {
            description + "-----\n" + &documentation_comment_to_markdown(documentation)
        }
    }
}

fn present_operator_declaration_info_markdown(
    module_origin_lookup: &ModuleOriginLookup,
    module_origin: &str,
    operator_symbol: Option<&str>,
    maybe_origin_operator_function_declaration: Option<(
        Option<&GrenSyntaxVariableDeclarationSignature>,
        Option<&str>,
    )>,
    maybe_documentation: Option<&str>,
    maybe_direction: Option<GrenSyntaxInfixDirection>,
    precedence: Option<i64>,
) -> String {
    match maybe_origin_operator_function_declaration {
        Some((
            origin_operator_function_maybe_signature,
            origin_operator_function_maybe_documentation,
        )) => {
            let description = format!(
                "```gren\ninfix {} {} {module_origin}.({}){}\n```\n",
                maybe_direction
                    .map(gren_syntax_infix_direction_to_str)
                    .unwrap_or(""),
                &precedence
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "".to_string()),
                operator_symbol.unwrap_or(""),
                &(match origin_operator_function_maybe_signature {
                    None => "".to_string(),
                    Some(origin_operator_function_signature) => {
                        match &origin_operator_function_signature.type_ {
                            None => "".to_string(),
                            Some(origin_operator_function_type) => {
                                " :".to_string()
                                    + match gren_syntax_range_line_span(
                                        origin_operator_function_type.range,
                                        &[], // no infix types have comments
                                    ) {
                                        LineSpan::Single => " ",
                                        LineSpan::Multiple => "\n    ",
                                    }
                                    + &gren_syntax_type_to_string(
                                        module_origin_lookup,
                                        gren_syntax_node_as_ref(origin_operator_function_type),
                                        4,
                                        &[], // no infix types have comments
                                    )
                            }
                        }
                    }
                })
            );
            match origin_operator_function_maybe_documentation {
                None => description,
                Some(documentation) => {
                    description + "-----\n" + &documentation_comment_to_markdown(documentation)
                }
            }
        }
        None => {
            let description = format!(
                "```gren\ninfix {} {} {module_origin}.({})\n```\n",
                maybe_direction
                    .map(gren_syntax_infix_direction_to_str)
                    .unwrap_or(""),
                precedence
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "".to_string()),
                operator_symbol.unwrap_or("")
            );
            match maybe_documentation {
                None => description,
                Some(documentation) => {
                    description + "-----\n" + &documentation_comment_to_markdown(documentation)
                }
            }
        }
    }
}
fn gren_syntax_infix_direction_to_str(direction: GrenSyntaxInfixDirection) -> &'static str {
    match direction {
        GrenSyntaxInfixDirection::Left => "left",
        GrenSyntaxInfixDirection::Non => "non",
        GrenSyntaxInfixDirection::Right => "right",
    }
}

fn respond_to_completion(
    state: &State,
    completion_arguments: &lsp_types::CompletionParams,
) -> Option<lsp_types::CompletionResponse> {
    let completion_project_module = state_get_project_module_by_lsp_url(
        state,
        &completion_arguments
            .text_document_position
            .text_document
            .uri,
    )?;
    let symbol_to_complete: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &completion_project_module.module.syntax,
            completion_arguments.text_document_position.position,
        )?;
    let maybe_completion_items: Option<Vec<lsp_types::CompletionItem>> = match symbol_to_complete
        .value
    {
        GrenSyntaxSymbol::ImportAlias { .. } => {
            // these are custom names you choose yourself, no need to suggest completion
            None
        }
        GrenSyntaxSymbol::ModuleName(module_name) => {
            Some(project_module_name_completions_for_except(
                state,
                completion_project_module.project,
                &[],
                module_name,
                completion_project_module
                    .module
                    .syntax
                    .header
                    .as_ref()
                    .and_then(|header| header.module_name.as_ref())
                    .map(|node| node.value.as_ref()),
            ))
        }
        GrenSyntaxSymbol::LetDeclarationName {
            name: _,
            start_name_range: _,
            signature_type: _,
            scope_expression,
        } => {
            match scope_expression.value {
                GrenSyntaxExpression::LetIn {
                    declarations: let_declarations,
                    in_keyword_range: _,
                    result: _,
                } => {
                    // find previous signature
                    let_declarations
                        .iter()
                        .zip(let_declarations.iter().skip(1))
                        .find_map(|(previous_declaration_node, current_declaration_node)| {
                            if let GrenSyntaxLetDeclaration::VariableDeclaration {
                                start_name: current_declaration_start_name_node,
                                signature: None,
                                ..
                            } = &current_declaration_node.value
                                && current_declaration_start_name_node.range
                                    == symbol_to_complete.range
                                && let GrenSyntaxLetDeclaration::VariableDeclaration {
                                    start_name: previous_declaration_start_name_node,
                                    signature:
                                        Some(GrenSyntaxVariableDeclarationSignature {
                                            implementation_name_range: None,
                                            ..
                                        }),
                                    ..
                                } = &previous_declaration_node.value
                            {
                                Some(vec![lsp_types::CompletionItem {
                                    label: previous_declaration_start_name_node.value.to_string(),
                                    kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                    documentation: None,
                                    ..lsp_types::CompletionItem::default()
                                }])
                            } else {
                                None
                            }
                        })
                }
                _ => None,
            }
        }
        GrenSyntaxSymbol::ModuleMemberDeclarationName { declaration, .. } => {
            match &declaration.value {
                GrenSyntaxDeclaration::ChoiceType { .. }
                | GrenSyntaxDeclaration::Port { .. }
                | GrenSyntaxDeclaration::Operator { .. }
                | GrenSyntaxDeclaration::TypeAlias { .. }
                | GrenSyntaxDeclaration::Variable {
                    signature: Some(_), ..
                } => {
                    // these are custom names you choose yourself, no need to suggest completion
                    None
                }
                GrenSyntaxDeclaration::Variable {
                    signature: None, ..
                } => {
                    // find previous signature
                    completion_project_module
                        .module
                        .syntax
                        .declarations
                        .iter()
                        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                        .zip(
                            completion_project_module
                                .module
                                .syntax
                                .declarations
                                .iter()
                                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                                .skip(1),
                        )
                        .find_map(|(previous_declaration, current_declaration)| {
                            if let Some(current_declaration_node) = &current_declaration.declaration
                                && let GrenSyntaxDeclaration::Variable {
                                    start_name: current_declaration_start_name_node,
                                    signature: None,
                                    ..
                                } = &current_declaration_node.value
                                && current_declaration_start_name_node.range
                                    == symbol_to_complete.range
                                && let Some(previous_declaration_node) =
                                    &previous_declaration.declaration
                                && let GrenSyntaxDeclaration::Variable {
                                    start_name: previous_declaration_start_name_node,
                                    signature:
                                        Some(GrenSyntaxVariableDeclarationSignature {
                                            implementation_name_range: None,
                                            ..
                                        }),
                                    ..
                                } = &previous_declaration_node.value
                            {
                                Some(vec![lsp_types::CompletionItem {
                                    label: previous_declaration_start_name_node.value.to_string(),
                                    kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                    documentation: None,
                                    ..lsp_types::CompletionItem::default()
                                }])
                            } else {
                                None
                            }
                        })
                }
            }
        }
        GrenSyntaxSymbol::ModuleHeaderExpose {
            name: to_complete_header_expose_name,
            all_exposes,
        } => {
            let module_origin: &str = completion_project_module
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let module_origin_lookup: ModuleOriginLookup = gren_syntax_module_create_origin_lookup(
                state,
                completion_project_module.project,
                &completion_project_module.module.syntax,
            );
            let existing_expose_names: std::collections::HashSet<&str> = all_exposes
                .iter()
                .filter_map(|expose_node| {
                    let expose_name: &str = match &expose_node.value {
                        GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                            name: open_choice_type_name,
                            open_range: _,
                        } => Some(open_choice_type_name.value.as_ref()),
                        GrenSyntaxExpose::Operator(operator_symbol) => {
                            operator_symbol.as_ref().map(|node| node.value)
                        }
                        GrenSyntaxExpose::Type(name) => Some(name.as_ref()),
                        GrenSyntaxExpose::Variable(name) => Some(name.as_ref()),
                    }?;
                    if expose_name == to_complete_header_expose_name {
                        None
                    } else {
                        Some(expose_name)
                    }
                })
                .collect::<std::collections::HashSet<_>>();
            let mut completion_items: Vec<lsp_types::CompletionItem> =
                Vec::with_capacity(completion_project_module.module.syntax.declarations.len());
            for (origin_module_declaration_node, origin_module_declaration_documentation) in
                completion_project_module
                    .module
                    .syntax
                    .declarations
                    .iter()
                    .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                    .filter_map(|documented_declaration| {
                        let declaration_node = documented_declaration.declaration.as_ref()?;
                        Some((
                            declaration_node,
                            documented_declaration
                                .documentation
                                .as_ref()
                                .map(|node| node.value.as_ref()),
                        ))
                    })
            {
                match &origin_module_declaration_node.value {
                    GrenSyntaxDeclaration::ChoiceType {
                        name: maybe_choice_type_name,
                        parameters,
                        equals_key_symbol_range: _,
                        variant0_name,
                        variant0_value: variant0_maybe_value,
                        variant1_up,
                    } => {
                        if let Some(choice_type_name_node) = maybe_choice_type_name
                            && !existing_expose_names.contains(choice_type_name_node.value.as_ref())
                        {
                            let info_markdown: String =
                                present_choice_type_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_origin,
                                    &completion_project_module.module.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(choice_type_name_node)),
                                    origin_module_declaration_documentation,
                                    parameters,
                                    variant0_name.as_ref().map(gren_syntax_node_unbox),
                                    variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                                    variant1_up,
                                );
                            completion_items.push(lsp_types::CompletionItem {
                                label: choice_type_name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::ENUM),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: info_markdown.clone(),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                            completion_items.push(lsp_types::CompletionItem {
                                label: format!("{}(..)", choice_type_name_node.value),
                                kind: Some(lsp_types::CompletionItemKind::ENUM),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: info_markdown,
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Port {
                        name: maybe_name,
                        colon_key_symbol_range: _,
                        type_,
                    } => {
                        if let Some(name_node) = maybe_name
                            && !existing_expose_names.contains(name_node.value.as_ref())
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_port_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            type_.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::TypeAlias {
                        alias_keyword_range: _,
                        name: maybe_name,
                        parameters,
                        equals_key_symbol_range: _,
                        type_: maybe_type,
                    } => {
                        if let Some(name_node) = maybe_name
                            && !existing_expose_names.contains(name_node.value.as_ref())
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::STRUCT),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_type_alias_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            parameters,
                                            maybe_type.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Variable {
                        start_name: start_name_node,
                        signature: maybe_signature,
                        parameters: _,
                        equals_key_symbol_range: _,
                        result: _,
                    } => {
                        if !existing_expose_names.contains(start_name_node.value.as_ref()) {
                            completion_items.push(lsp_types::CompletionItem {
                                label: start_name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_variable_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            gren_syntax_node_unbox(start_name_node),
                                            origin_module_declaration_documentation,
                                            maybe_signature
                                                .as_ref()
                                                .and_then(|signature| signature.type_.as_ref())
                                                .map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Operator { .. } => {
                        // no new operators will ever be added
                    }
                }
            }
            Some(completion_items)
        }
        GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
            name: to_complete_header_expose_name,
            module_documentation,
        } => {
            let module_origin: &str = completion_project_module
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref())
                .unwrap_or("");
            let module_origin_lookup: ModuleOriginLookup = gren_syntax_module_create_origin_lookup(
                state,
                completion_project_module.project,
                &completion_project_module.module.syntax,
            );
            let existing_member_names_across_at_docs: std::collections::HashSet<&str> =
                module_documentation
                    .iter()
                    .flat_map(|module_documentation_element| {
                        match &module_documentation_element.value {
                            GrenSyntaxModuleDocumentationElement::Markdown(_) => None,
                            GrenSyntaxModuleDocumentationElement::AtDocs(at_docs_member_names) => {
                                Some(
                                    at_docs_member_names
                                        .iter()
                                        .map(|node| node.value.as_ref())
                                        .filter(|&member_name| {
                                            member_name != to_complete_header_expose_name
                                        }),
                                )
                            }
                        }
                        .into_iter()
                        .flatten()
                    })
                    .collect::<std::collections::HashSet<_>>();
            let mut completion_items: Vec<lsp_types::CompletionItem> = Vec::new();
            for (origin_module_declaration_node, origin_module_declaration_documentation) in
                completion_project_module
                    .module
                    .syntax
                    .declarations
                    .iter()
                    .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                    .filter_map(|documented_declaration| {
                        let declaration_node = documented_declaration.declaration.as_ref()?;
                        Some((
                            declaration_node,
                            documented_declaration
                                .documentation
                                .as_ref()
                                .map(|node| node.value.as_ref()),
                        ))
                    })
            {
                match &origin_module_declaration_node.value {
                    GrenSyntaxDeclaration::ChoiceType {
                        name: maybe_choice_type_name,
                        parameters,
                        equals_key_symbol_range: _,
                        variant0_name,
                        variant0_value: variant0_maybe_value,
                        variant1_up,
                    } => {
                        if let Some(choice_type_name_node) = maybe_choice_type_name
                            && !existing_member_names_across_at_docs
                                .contains(choice_type_name_node.value.as_ref())
                        {
                            let info_markdown: String =
                                present_choice_type_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_origin,
                                    &completion_project_module.module.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(choice_type_name_node)),
                                    origin_module_declaration_documentation,
                                    parameters,
                                    variant0_name.as_ref().map(gren_syntax_node_unbox),
                                    variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                                    variant1_up,
                                );
                            completion_items.push(lsp_types::CompletionItem {
                                label: choice_type_name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::ENUM_MEMBER),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        // should the documentation code indicate the variants are hidden?
                                        value: info_markdown.clone(),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Port {
                        name: maybe_name,
                        colon_key_symbol_range: _,
                        type_,
                    } => {
                        if let Some(name_node) = maybe_name
                            && !existing_member_names_across_at_docs
                                .contains(name_node.value.as_ref())
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_port_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            type_.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::TypeAlias {
                        alias_keyword_range: _,
                        name: maybe_name,
                        parameters,
                        equals_key_symbol_range: _,
                        type_: maybe_type,
                    } => {
                        if let Some(name_node) = maybe_name
                            && !existing_member_names_across_at_docs
                                .contains(name_node.value.as_ref())
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::STRUCT),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_type_alias_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            parameters,
                                            maybe_type.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Variable {
                        start_name: start_name_node,
                        signature: maybe_signature,
                        parameters: _,
                        equals_key_symbol_range: _,
                        result: _,
                    } => {
                        if !existing_member_names_across_at_docs
                            .contains(start_name_node.value.as_ref())
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: start_name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_variable_declaration_info_markdown(
                                            &module_origin_lookup,
                                            module_origin,
                                            &completion_project_module.module.syntax.comments,
                                            gren_syntax_node_unbox(start_name_node),
                                            origin_module_declaration_documentation,
                                            maybe_signature
                                                .as_ref()
                                                .and_then(|signature| signature.type_.as_ref())
                                                .map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Operator { .. } => {
                        // no new operators will ever be added
                    }
                }
            }
            Some(completion_items)
        }
        GrenSyntaxSymbol::ImportExpose {
            origin_module: to_complete_module_origin,
            name: to_complete_import_expose_name,
            all_exposes,
        } => {
            let (_, import_origin_module_state) = project_state_get_module_with_name(
                state,
                completion_project_module.project,
                to_complete_module_origin,
            )?;
            let import_module_origin_lookup: ModuleOriginLookup =
                gren_syntax_module_create_origin_lookup(
                    state,
                    completion_project_module.project,
                    &import_origin_module_state.syntax,
                );
            let existing_import_expose_names: std::collections::HashSet<&str> = all_exposes
                .iter()
                .filter_map(|expose_node| match &expose_node.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name: open_choice_type_name,
                        open_range: _,
                    } => Some(open_choice_type_name.value.as_ref()),
                    GrenSyntaxExpose::Operator(operator_symbol) => {
                        operator_symbol.as_ref().map(|node| node.value)
                    }
                    GrenSyntaxExpose::Type(name) => Some(name.as_ref()),
                    GrenSyntaxExpose::Variable(name) => Some(name.as_ref()),
                })
                .collect::<std::collections::HashSet<_>>();
            let import_origin_module_expose_set: GrenExposeSet =
                gren_syntax_module_header_expose_set(
                    import_origin_module_state.syntax.header.as_ref(),
                );
            let import_origin_module_declaration_can_still_be_import_expose = |name: &str| -> bool {
                gren_expose_set_contains(&import_origin_module_expose_set, name)
                    && (name == to_complete_import_expose_name
                        || !existing_import_expose_names.contains(name))
            };
            let mut completion_items: Vec<lsp_types::CompletionItem> = Vec::new();
            for (origin_module_declaration_node, origin_module_declaration_documentation) in
                import_origin_module_state
                    .syntax
                    .declarations
                    .iter()
                    .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                    .filter_map(|documented_declaration| {
                        documented_declaration
                            .declaration
                            .as_ref()
                            .map(|declaration_node| {
                                (
                                    declaration_node,
                                    documented_declaration
                                        .documentation
                                        .as_ref()
                                        .map(|node| node.value.as_ref()),
                                )
                            })
                    })
            {
                match &origin_module_declaration_node.value {
                    GrenSyntaxDeclaration::ChoiceType {
                        name: maybe_choice_type_name,
                        parameters,
                        equals_key_symbol_range: _,
                        variant0_name,
                        variant0_value: variant0_maybe_value,
                        variant1_up,
                    } => {
                        if let Some(choice_type_name_node) = maybe_choice_type_name
                            && import_origin_module_declaration_can_still_be_import_expose(
                                choice_type_name_node.value.as_ref(),
                            )
                        {
                            let info_markdown: String = format!(
                                "variant in\n{}",
                                present_choice_type_declaration_info_markdown(
                                    &import_module_origin_lookup,
                                    to_complete_module_origin,
                                    &import_origin_module_state.syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(choice_type_name_node)),
                                    origin_module_declaration_documentation,
                                    parameters,
                                    variant0_name
                                        .as_ref()
                                        .map(|node| { gren_syntax_node_unbox(node) }),
                                    variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                                    variant1_up,
                                ),
                            );
                            completion_items.extend(
                                variant0_name
                                    .as_ref()
                                    .map(|node| node.value.to_string())
                                    .into_iter()
                                    .chain(variant1_up.iter().filter_map(|variant| {
                                        variant.name.as_ref().map(|node| node.value.to_string())
                                    }))
                                    .map(|variant_name| lsp_types::CompletionItem {
                                        label: variant_name,
                                        kind: Some(lsp_types::CompletionItemKind::ENUM_MEMBER),
                                        documentation: Some(
                                            lsp_types::Documentation::MarkupContent(
                                                lsp_types::MarkupContent {
                                                    kind: lsp_types::MarkupKind::Markdown,
                                                    value: info_markdown.clone(),
                                                },
                                            ),
                                        ),
                                        ..lsp_types::CompletionItem::default()
                                    }),
                            );
                        }
                    }
                    GrenSyntaxDeclaration::Port {
                        name,
                        colon_key_symbol_range: _,
                        type_,
                    } => {
                        if let Some(name_node) = name
                            && import_origin_module_declaration_can_still_be_import_expose(
                                name_node.value.as_ref(),
                            )
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_port_declaration_info_markdown(
                                            &import_module_origin_lookup,
                                            to_complete_module_origin,
                                            &import_origin_module_state.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            type_.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::TypeAlias {
                        alias_keyword_range: _,
                        name: maybe_name,
                        parameters,
                        equals_key_symbol_range: _,
                        type_: maybe_type,
                    } => {
                        if let Some(name_node) = maybe_name
                            && import_origin_module_declaration_can_still_be_import_expose(
                                name_node.value.as_ref(),
                            )
                        {
                            completion_items.push(lsp_types::CompletionItem {
                                label: name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::STRUCT),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_type_alias_declaration_info_markdown(
                                            &import_module_origin_lookup,
                                            to_complete_module_origin,
                                            &import_origin_module_state.syntax.comments,
                                            origin_module_declaration_node.range,
                                            Some(gren_syntax_node_unbox(name_node)),
                                            origin_module_declaration_documentation,
                                            parameters,
                                            maybe_type.as_ref().map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Variable {
                        start_name: start_name_node,
                        signature: maybe_signature,
                        parameters: _,
                        equals_key_symbol_range: _,
                        result: _,
                    } => {
                        if import_origin_module_declaration_can_still_be_import_expose(
                            start_name_node.value.as_ref(),
                        ) {
                            completion_items.push(lsp_types::CompletionItem {
                                label: start_name_node.value.to_string(),
                                kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_variable_declaration_info_markdown(
                                            &import_module_origin_lookup,
                                            to_complete_module_origin,
                                            &import_origin_module_state.syntax.comments,
                                            gren_syntax_node_unbox(start_name_node),
                                            origin_module_declaration_documentation,
                                            maybe_signature
                                                .as_ref()
                                                .and_then(|signature| signature.type_.as_ref())
                                                .map(gren_syntax_node_as_ref),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                    GrenSyntaxDeclaration::Operator {
                        direction: maybe_direction,
                        precedence: maybe_precedence,
                        operator: maybe_operator,
                        equals_key_symbol_range: _,
                        function: maybe_function,
                    } => {
                        if let Some(operator_node) = maybe_operator
                            && import_origin_module_declaration_can_still_be_import_expose(
                                operator_node.value,
                            )
                        {
                            let maybe_origin_operator_function_declaration = maybe_function
                                .as_ref()
                                .and_then(|origin_module_declaration_function_node| {
                                    import_origin_module_state
                                        .syntax
                                        .declarations
                                        .iter()
                                        .filter_map(|declaration_or_err| {
                                            declaration_or_err.as_ref().ok()
                                        })
                                        .find_map(|origin_module_potential_function_declaration| {
                                            let origin_module_potential_function_declaration_node =
                                                origin_module_potential_function_declaration
                                                    .declaration
                                                    .as_ref()?;
                                            match &origin_module_potential_function_declaration_node
                                                .value
                                            {
                                                GrenSyntaxDeclaration::Variable {
                                                    start_name: origin_module_declaration_name,
                                                    signature: origin_module_declaration_signature,
                                                    ..
                                                } if origin_module_declaration_name.value
                                                    == origin_module_declaration_function_node
                                                        .value =>
                                                {
                                                    Some((
                                                        origin_module_declaration_signature
                                                            .as_ref(),
                                                        origin_module_potential_function_declaration
                                                            .documentation
                                                            .as_ref()
                                                            .map(|node| node.value.as_ref()),
                                                    ))
                                                }
                                                _ => None,
                                            }
                                        })
                                });
                            completion_items.push(lsp_types::CompletionItem {
                                label: format!("({})", operator_node.value),
                                kind: Some(lsp_types::CompletionItemKind::OPERATOR),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: present_operator_declaration_info_markdown(
                                            &import_module_origin_lookup,
                                            to_complete_module_origin,
                                            Some(operator_node.value),
                                            maybe_origin_operator_function_declaration,
                                            origin_module_declaration_documentation,
                                            maybe_direction.map(|node| node.value),
                                            maybe_precedence.map(|node| node.value),
                                        ),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            });
                        }
                    }
                }
            }
            Some(completion_items)
        }
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification: to_complete_qualification,
            name: to_complete_name,
            local_bindings,
        } => {
            let maybe_completion_module_name: Option<&str> = completion_project_module
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref());
            let full_name_to_complete: String = if to_complete_qualification.is_empty() {
                to_complete_name.to_string()
            } else {
                format!("{to_complete_qualification}.{to_complete_name}")
            };
            let to_complete_module_import_alias_origin_lookup: Vec<GrenImportAliasAndModuleOrigin> =
                gren_syntax_imports_create_import_alias_origin_lookup(
                    &completion_project_module.module.syntax.imports,
                );
            let mut completion_items: Vec<lsp_types::CompletionItem> = Vec::new();
            if (to_complete_name.is_empty()) || to_complete_name.starts_with(char::is_uppercase) {
                completion_items.extend(project_module_name_completions_for_except(
                    state,
                    completion_project_module.project,
                    &to_complete_module_import_alias_origin_lookup,
                    &full_name_to_complete,
                    maybe_completion_module_name,
                ));
            }
            if to_complete_qualification.is_empty() {
                let local_binding_completions = local_bindings
                    .into_iter()
                    .flat_map(|(_, scope_introduced_bindings)| {
                        scope_introduced_bindings.into_iter()
                    })
                    .map(|local_binding| lsp_types::CompletionItem {
                        label: local_binding.name.to_string(),
                        kind: Some(lsp_types::CompletionItemKind::VARIABLE),
                        documentation: Some(lsp_types::Documentation::MarkupContent(
                            lsp_types::MarkupContent {
                                kind: lsp_types::MarkupKind::Markdown,
                                value: local_binding_info_markdown(
                                    state,
                                    completion_project_module.project,
                                    &completion_project_module.module.syntax,
                                    local_binding.name,
                                    local_binding.origin,
                                ),
                            },
                        )),
                        ..lsp_types::CompletionItem::default()
                    });
                completion_items.extend(local_binding_completions);
                variable_declaration_completions_into(
                    state,
                    completion_project_module.project,
                    &completion_project_module.module.syntax,
                    &mut completion_items,
                    &GrenExposeSet::All,
                );
                for (import_module_origin, import_expose_set) in completion_project_module
                    .module
                    .syntax
                    .imports
                    .iter()
                    .filter_map(|import_node| {
                        let module_name_node = import_node.value.module_name.as_ref()?;
                        let exposing_node = import_node.value.exposing.as_ref()?;
                        Some((
                            &module_name_node.value,
                            gren_syntax_exposing_to_set(&exposing_node.value),
                        ))
                    })
                {
                    if let Some((_, import_module_state)) = project_state_get_module_with_name(
                        state,
                        completion_project_module.project,
                        import_module_origin,
                    ) {
                        let import_module_expose_set: GrenExposeSet = match import_expose_set {
                            GrenExposeSet::All => gren_syntax_module_header_expose_set(
                                import_module_state.syntax.header.as_ref(),
                            ),
                            GrenExposeSet::Explicit { .. } => import_expose_set,
                        };
                        variable_declaration_completions_into(
                            state,
                            completion_project_module.project,
                            &import_module_state.syntax,
                            &mut completion_items,
                            &import_module_expose_set,
                        );
                    }
                }
            }
            if !to_complete_qualification.is_empty() {
                let to_complete_module_origins: Vec<&str> = look_up_import_alias_module_origins(
                    &to_complete_module_import_alias_origin_lookup,
                    to_complete_qualification,
                )
                .unwrap_or_else(|| vec![to_complete_qualification]);
                for to_complete_module_origin in to_complete_module_origins {
                    if let Some((_, to_complete_origin_module_state)) =
                        project_state_get_module_with_name(
                            state,
                            completion_project_module.project,
                            to_complete_module_origin,
                        )
                    {
                        let origin_module_expose_set: GrenExposeSet =
                            gren_syntax_module_header_expose_set(
                                to_complete_origin_module_state.syntax.header.as_ref(),
                            );
                        variable_declaration_completions_into(
                            state,
                            completion_project_module.project,
                            &to_complete_origin_module_state.syntax,
                            &mut completion_items,
                            &origin_module_expose_set,
                        );
                    }
                }
            }
            Some(completion_items)
        }
        GrenSyntaxSymbol::Type {
            qualification: to_complete_qualification,
            name: to_complete_name,
        } => {
            let maybe_completion_module_name: Option<&str> = completion_project_module
                .module
                .syntax
                .header
                .as_ref()
                .and_then(|header| header.module_name.as_ref())
                .map(|node| node.value.as_ref());
            let full_name_to_complete: String = if to_complete_qualification.is_empty() {
                to_complete_name.to_string()
            } else {
                format!("{to_complete_qualification}.{to_complete_name}")
            };
            let to_complete_module_import_alias_origin_lookup: Vec<GrenImportAliasAndModuleOrigin> =
                gren_syntax_imports_create_import_alias_origin_lookup(
                    &completion_project_module.module.syntax.imports,
                );
            let mut completion_items: Vec<lsp_types::CompletionItem> =
                project_module_name_completions_for_except(
                    state,
                    completion_project_module.project,
                    &to_complete_module_import_alias_origin_lookup,
                    &full_name_to_complete,
                    maybe_completion_module_name,
                );
            if to_complete_qualification.is_empty() {
                type_declaration_completions_into(
                    state,
                    completion_project_module.project,
                    &completion_project_module.module.syntax,
                    &mut completion_items,
                    &GrenExposeSet::All,
                );
                for (import_module_origin, import_expose_set) in completion_project_module
                    .module
                    .syntax
                    .imports
                    .iter()
                    .filter_map(|import_node| {
                        let module_name_node = import_node.value.module_name.as_ref()?;
                        let exposing_node = import_node.value.exposing.as_ref()?;
                        Some((
                            &module_name_node.value,
                            gren_syntax_exposing_to_set(&exposing_node.value),
                        ))
                    })
                {
                    if let Some((_, import_module_state)) = project_state_get_module_with_name(
                        state,
                        completion_project_module.project,
                        import_module_origin,
                    ) {
                        let import_module_expose_set: GrenExposeSet = match import_expose_set {
                            GrenExposeSet::All => gren_syntax_module_header_expose_set(
                                import_module_state.syntax.header.as_ref(),
                            ),
                            GrenExposeSet::Explicit { .. } => import_expose_set,
                        };
                        type_declaration_completions_into(
                            state,
                            completion_project_module.project,
                            &import_module_state.syntax,
                            &mut completion_items,
                            &import_module_expose_set,
                        );
                    }
                }
            }
            if !to_complete_qualification.is_empty() {
                let to_complete_module_origins: Vec<&str> = look_up_import_alias_module_origins(
                    &to_complete_module_import_alias_origin_lookup,
                    to_complete_qualification,
                )
                .unwrap_or_else(|| vec![to_complete_qualification]);
                for to_complete_module_origin in to_complete_module_origins {
                    if let Some((_, to_complete_origin_module_state)) =
                        project_state_get_module_with_name(
                            state,
                            completion_project_module.project,
                            to_complete_module_origin,
                        )
                    {
                        let origin_module_expose_set: GrenExposeSet =
                            gren_syntax_module_header_expose_set(
                                to_complete_origin_module_state.syntax.header.as_ref(),
                            );
                        type_declaration_completions_into(
                            state,
                            completion_project_module.project,
                            &to_complete_origin_module_state.syntax,
                            &mut completion_items,
                            &origin_module_expose_set,
                        );
                    }
                }
            }
            Some(completion_items)
        }
        GrenSyntaxSymbol::TypeVariable { .. } => {
            // is this ever useful to add? gren tends to use single-letter names anyway most of the time
            // (or ones where the first letters don't match in the first place).
            // suggesting completions can get annoying and isn't free computationally so...
            None
        }
    };
    maybe_completion_items.map(lsp_types::CompletionResponse::Array)
}

fn variable_declaration_completions_into(
    state: &State,
    project_state: &ProjectState,
    module_syntax: &GrenSyntaxModule,
    completion_items: &mut Vec<lsp_types::CompletionItem>,
    expose_set: &GrenExposeSet,
) {
    let module_name: &str = module_syntax
        .header
        .as_ref()
        .and_then(|header| header.module_name.as_ref())
        .map(|node| node.value.as_ref())
        .unwrap_or("");
    let module_origin_lookup: ModuleOriginLookup =
        gren_syntax_module_create_origin_lookup(state, project_state, module_syntax);
    for (origin_module_declaration_node, origin_module_declaration_documentation) in module_syntax
        .declarations
        .iter()
        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
        .filter_map(|documented_declaration| {
            documented_declaration
                .declaration
                .as_ref()
                .map(|declaration_node| {
                    (
                        declaration_node,
                        documented_declaration
                            .documentation
                            .as_ref()
                            .map(|node| node.value.as_ref()),
                    )
                })
        })
    {
        match &origin_module_declaration_node.value {
            GrenSyntaxDeclaration::ChoiceType {
                name: maybe_choice_type_name,
                parameters,
                equals_key_symbol_range: _,
                variant0_name,
                variant0_value: variant0_maybe_value,
                variant1_up,
            } => {
                if let Some(choice_type_name_node) = maybe_choice_type_name
                    && gren_expose_set_contains_choice_type_including_variants(
                        expose_set,
                        &choice_type_name_node.value,
                    )
                {
                    let info_markdown: String = format!(
                        "variant in\n{}",
                        present_choice_type_declaration_info_markdown(
                            &module_origin_lookup,
                            module_name,
                            &module_syntax.comments,
                            origin_module_declaration_node.range,
                            Some(gren_syntax_node_unbox(choice_type_name_node)),
                            origin_module_declaration_documentation,
                            parameters,
                            variant0_name.as_ref().map(gren_syntax_node_unbox),
                            variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                            variant1_up,
                        ),
                    );
                    completion_items.extend(
                        variant0_name
                            .as_ref()
                            .map(|node| node.value.to_string())
                            .into_iter()
                            .chain(variant1_up.iter().filter_map(|variant| {
                                variant.name.as_ref().map(|node| node.value.to_string())
                            }))
                            .map(|variant_name: String| lsp_types::CompletionItem {
                                label: variant_name,
                                kind: Some(lsp_types::CompletionItemKind::ENUM_MEMBER),
                                documentation: Some(lsp_types::Documentation::MarkupContent(
                                    lsp_types::MarkupContent {
                                        kind: lsp_types::MarkupKind::Markdown,
                                        value: info_markdown.clone(),
                                    },
                                )),
                                ..lsp_types::CompletionItem::default()
                            }),
                    );
                }
            }
            GrenSyntaxDeclaration::Port {
                name: maybe_name,
                colon_key_symbol_range: _,
                type_,
            } => {
                if let Some(name_node) = maybe_name
                    && gren_expose_set_contains_variable(expose_set, &name_node.value)
                {
                    completion_items.push(lsp_types::CompletionItem {
                        label: name_node.value.to_string(),
                        kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                        documentation: Some(lsp_types::Documentation::MarkupContent(
                            lsp_types::MarkupContent {
                                kind: lsp_types::MarkupKind::Markdown,
                                value: present_port_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_name,
                                    &module_syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(name_node)),
                                    origin_module_declaration_documentation,
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ),
                            },
                        )),
                        ..lsp_types::CompletionItem::default()
                    });
                }
            }
            GrenSyntaxDeclaration::TypeAlias { .. } => {}
            GrenSyntaxDeclaration::Variable {
                start_name: start_name_node,
                signature: maybe_signature,
                parameters: _,
                equals_key_symbol_range: _,
                result: _,
            } => {
                if gren_expose_set_contains_variable(expose_set, &start_name_node.value) {
                    completion_items.push(lsp_types::CompletionItem {
                        label: start_name_node.value.to_string(),
                        kind: Some(lsp_types::CompletionItemKind::FUNCTION),
                        documentation: Some(lsp_types::Documentation::MarkupContent(
                            lsp_types::MarkupContent {
                                kind: lsp_types::MarkupKind::Markdown,
                                value: present_variable_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_name,
                                    &module_syntax.comments,
                                    gren_syntax_node_unbox(start_name_node),
                                    origin_module_declaration_documentation,
                                    maybe_signature
                                        .as_ref()
                                        .and_then(|signature| signature.type_.as_ref())
                                        .map(gren_syntax_node_as_ref),
                                ),
                            },
                        )),
                        ..lsp_types::CompletionItem::default()
                    });
                }
            }
            GrenSyntaxDeclaration::Operator { .. } => {
                // suggesting operators is really confusing I think.
                // Also, wether it needs to be surrounded by parens
                // is not super easy to find out
            }
        }
    }
}
fn type_declaration_completions_into(
    state: &State,
    project_state: &ProjectState,
    module_syntax: &GrenSyntaxModule,
    completion_items: &mut Vec<lsp_types::CompletionItem>,
    expose_set: &GrenExposeSet,
) {
    let module_name: &str = module_syntax
        .header
        .as_ref()
        .and_then(|header| header.module_name.as_ref())
        .map(|node| node.value.as_ref())
        .unwrap_or("");
    let module_origin_lookup: ModuleOriginLookup =
        gren_syntax_module_create_origin_lookup(state, project_state, module_syntax);
    for (origin_module_declaration_node, origin_module_declaration_documentation) in module_syntax
        .declarations
        .iter()
        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
        .filter_map(|documented_declaration| {
            documented_declaration
                .declaration
                .as_ref()
                .map(|declaration_node| {
                    (
                        declaration_node,
                        documented_declaration
                            .documentation
                            .as_ref()
                            .map(|node| node.value.as_ref()),
                    )
                })
        })
    {
        match &origin_module_declaration_node.value {
            GrenSyntaxDeclaration::ChoiceType {
                name: maybe_name,
                parameters,
                equals_key_symbol_range: _,
                variant0_name: maybe_variant0_name,
                variant0_value: variant0_maybe_value,
                variant1_up,
            } => {
                if let Some(name_node) = maybe_name.as_ref()
                    && gren_expose_set_contains_type(expose_set, &name_node.value)
                {
                    completion_items.push(lsp_types::CompletionItem {
                        label: name_node.value.to_string(),
                        kind: Some(lsp_types::CompletionItemKind::ENUM),
                        documentation: Some(lsp_types::Documentation::MarkupContent(
                            lsp_types::MarkupContent {
                                kind: lsp_types::MarkupKind::Markdown,
                                value: present_choice_type_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_name,
                                    &module_syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(name_node)),
                                    origin_module_declaration_documentation,
                                    parameters,
                                    maybe_variant0_name.as_ref().map(gren_syntax_node_unbox),
                                    variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                                    variant1_up,
                                ),
                            },
                        )),
                        ..lsp_types::CompletionItem::default()
                    });
                }
            }
            GrenSyntaxDeclaration::TypeAlias {
                alias_keyword_range: _,
                name: maybe_name,
                parameters,
                equals_key_symbol_range: _,
                type_,
            } => {
                if let Some(name_node) = maybe_name.as_ref()
                    && gren_expose_set_contains_type_not_including_variants(
                        expose_set,
                        &name_node.value,
                    )
                {
                    completion_items.push(lsp_types::CompletionItem {
                        label: name_node.value.to_string(),
                        kind: Some(lsp_types::CompletionItemKind::STRUCT),
                        documentation: Some(lsp_types::Documentation::MarkupContent(
                            lsp_types::MarkupContent {
                                kind: lsp_types::MarkupKind::Markdown,
                                value: present_type_alias_declaration_info_markdown(
                                    &module_origin_lookup,
                                    module_name,
                                    &module_syntax.comments,
                                    origin_module_declaration_node.range,
                                    Some(gren_syntax_node_unbox(name_node)),
                                    origin_module_declaration_documentation,
                                    parameters,
                                    type_.as_ref().map(gren_syntax_node_as_ref),
                                ),
                            },
                        )),
                        ..lsp_types::CompletionItem::default()
                    });
                }
            }
            GrenSyntaxDeclaration::Port { .. } => {}
            GrenSyntaxDeclaration::Variable { .. } => {}
            GrenSyntaxDeclaration::Operator { .. } => {}
        }
    }
}

fn respond_to_document_formatting(
    state: &State,
    formatting_arguments: &lsp_types::DocumentFormattingParams,
) -> Option<Vec<lsp_types::TextEdit>> {
    let document_path: std::path::PathBuf =
        formatting_arguments.text_document.uri.to_file_path().ok()?;
    let to_format_project_module = state_get_project_module_by_path(state, &document_path)?;
    let formatted: String = match &state.configured_gren_formatter {
        Some(ConfiguredGrenFormatter::Builtin) | None => {
            gren_syntax_module_format(to_format_project_module.module)
        }
        Some(ConfiguredGrenFormatter::Custom {
            path: configured_gren_format_path,
        }) => format_using_gren_format(
            configured_gren_format_path,
            to_format_project_module.project_path,
            &to_format_project_module.module.source,
        )?,
    };
    // diffing does not seem to be needed here. But maybe it's faster?
    Some(vec![lsp_types::TextEdit {
        range: lsp_types::Range {
            start: lsp_types::Position {
                line: 0,
                character: 0,
            },
            end: lsp_types::Position {
                line: 1_000_000_000, // to_format_project_module.module.source.lines().count() as u32 + 1
                character: 0,
            },
        },
        new_text: formatted,
    }])
}
fn format_using_gren_format(
    configured_gren_format_path: &str,
    project_path: &std::path::Path,
    source: &str,
) -> Option<String> {
    let mut gren_format_cmd: std::process::Command =
        std::process::Command::new(configured_gren_format_path);
    gren_format_cmd
        .args(["--stdin", "--gren-version", "0.19", "--yes"])
        .current_dir(project_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut gren_format_process: std::process::Child = gren_format_cmd
        .spawn()
        .map_err(|error| {
            eprintln!("running {configured_gren_format_path} failed: {error}.");
        })
        .ok()?;
    {
        // explicit block is necessary to close writing input before blocking for output
        // (otherwise both processes wait, quite the footgun in honestly)
        let mut stdin: std::process::ChildStdin =
            gren_format_process.stdin.take().or_else(|| {
                eprintln!("couldn't open {configured_gren_format_path} stdin");
                let _ = gren_format_process.wait();
                None
            })?;
        std::io::Write::write_all(&mut stdin, source.as_bytes())
            .map_err(|error| {
                eprintln!("couldn't write to {configured_gren_format_path} stdin: {error}");
                let _ = gren_format_process.wait();
            })
            .ok()?;
    }
    let output: std::process::Output = gren_format_process
        .wait_with_output()
        .map_err(|error| {
            eprintln!("couldn't read from {configured_gren_format_path} stdout: {error}");
        })
        .ok()?; // ignore output in case of parse errors
    if !output.stderr.is_empty() {
        // parse error, not worth logging
        return None;
    }
    String::from_utf8(output.stdout)
        .map_err(|error| {
            eprintln!(
                "couldn't read from {configured_gren_format_path} stdout as UTF-8 string: {error}"
            );
        })
        .ok()
}

fn respond_to_document_symbols(
    state: &State,
    document_symbol_arguments: &lsp_types::DocumentSymbolParams,
) -> Option<lsp_types::DocumentSymbolResponse> {
    let document_path: std::path::PathBuf = document_symbol_arguments
        .text_document
        .uri
        .to_file_path()
        .ok()?;
    let project_module = state_get_project_module_by_path(state, &document_path)?;
    Some(lsp_types::DocumentSymbolResponse::Nested(
        project_module
            .module
            .syntax
            .declarations
            .iter()
            .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
            .filter_map(|documented_declaration| documented_declaration.declaration.as_ref())
            .filter_map(|declaration_node| match &declaration_node.value {
                GrenSyntaxDeclaration::ChoiceType {
                    name: maybe_name,
                    parameters: _,
                    equals_key_symbol_range: _,
                    variant0_name,
                    variant0_value: variant0_maybe_value,
                    variant1_up,
                } => {
                    let name_node = maybe_name.as_ref()?;
                    Some(lsp_types::DocumentSymbol {
                        name: name_node.value.to_string(),
                        detail: None,
                        kind: lsp_types::SymbolKind::ENUM,
                        tags: None,
                        #[allow(deprecated)]
                        deprecated: None,
                        range: declaration_node.range,
                        selection_range: name_node.range,
                        children: Some(
                            variant0_name
                                .as_ref()
                                .map(|variant0_name_node| {
                                    (
                                        variant0_name_node,
                                        lsp_types::Range {
                                            start: variant0_name_node.range.start,
                                            end: variant0_maybe_value
                                                .as_ref()
                                                .map(|node| node.range.end)
                                                .unwrap_or(variant0_name_node.range.end),
                                        },
                                    )
                                })
                                .into_iter()
                                .chain(variant1_up.iter().filter_map(|variant| {
                                    let variant_name_node = variant.name.as_ref()?;
                                    Some((
                                        variant_name_node,
                                        lsp_types::Range {
                                            start: variant_name_node.range.start,
                                            end: variant
                                                .value
                                                .as_ref()
                                                .map(|node| node.range.end)
                                                .unwrap_or(variant_name_node.range.end),
                                        },
                                    ))
                                }))
                                .map(|(variant_name_node, variant_full_range)| {
                                    lsp_types::DocumentSymbol {
                                        name: variant_name_node.value.to_string(),
                                        detail: None,
                                        kind: lsp_types::SymbolKind::ENUM_MEMBER,
                                        tags: None,
                                        #[allow(deprecated)]
                                        deprecated: None,
                                        range: variant_full_range,
                                        selection_range: variant_name_node.range,
                                        children: None,
                                    }
                                })
                                .collect::<Vec<_>>(),
                        ),
                    })
                }
                GrenSyntaxDeclaration::Operator {
                    operator: maybe_operator,
                    direction: _,
                    precedence: _,
                    equals_key_symbol_range: _,
                    function: _,
                } => {
                    let operator_node = maybe_operator.as_ref()?;
                    Some(lsp_types::DocumentSymbol {
                        name: operator_node.value.to_string(),
                        detail: None,
                        kind: lsp_types::SymbolKind::OPERATOR,
                        tags: None,
                        #[allow(deprecated)]
                        deprecated: None,
                        range: declaration_node.range,
                        selection_range: operator_node.range,
                        children: None,
                    })
                }
                GrenSyntaxDeclaration::Port {
                    name: maybe_name,
                    colon_key_symbol_range: _,
                    type_: _,
                } => {
                    let name_node = maybe_name.as_ref()?;
                    Some(lsp_types::DocumentSymbol {
                        name: name_node.value.to_string(),
                        detail: None,
                        kind: lsp_types::SymbolKind::FUNCTION,
                        tags: None,
                        #[allow(deprecated)]
                        deprecated: None,
                        range: declaration_node.range,
                        selection_range: name_node.range,
                        children: None,
                    })
                }
                GrenSyntaxDeclaration::TypeAlias {
                    name: maybe_name,
                    alias_keyword_range: _,
                    parameters: _,
                    equals_key_symbol_range: _,
                    type_: _,
                } => {
                    let name_node = maybe_name.as_ref()?;
                    Some(lsp_types::DocumentSymbol {
                        name: name_node.value.to_string(),
                        detail: None,
                        kind: lsp_types::SymbolKind::STRUCT,
                        tags: None,
                        #[allow(deprecated)]
                        deprecated: None,
                        range: declaration_node.range,
                        selection_range: name_node.range,
                        children: None,
                    })
                }
                GrenSyntaxDeclaration::Variable {
                    start_name: start_name_node,
                    signature: _,
                    parameters: _,
                    equals_key_symbol_range: _,
                    result: _,
                } => Some(lsp_types::DocumentSymbol {
                    name: start_name_node.value.to_string(),
                    detail: None,
                    kind: lsp_types::SymbolKind::FUNCTION,
                    tags: None,
                    #[allow(deprecated)]
                    deprecated: None,
                    range: declaration_node.range,
                    selection_range: start_name_node.range,
                    children: None,
                }),
            })
            .collect::<Vec<_>>(),
    ))
}
fn respond_to_code_action(
    state: &State,
    code_action_arguments: lsp_types::CodeActionParams,
) -> Option<Vec<lsp_types::CodeActionOrCommand>> {
    let document_path: std::path::PathBuf = code_action_arguments
        .text_document
        .uri
        .to_file_path()
        .ok()?;
    let project_module_state = state_get_project_module_by_path(state, &document_path)?;
    let code_action_symbol_node: GrenSyntaxNode<GrenSyntaxSymbol> =
        gren_syntax_module_find_symbol_at_position(
            &project_module_state.module.syntax,
            code_action_arguments.range.start,
        )?;
    match code_action_symbol_node.value {
        GrenSyntaxSymbol::ModuleName(_) => None,
        GrenSyntaxSymbol::ImportAlias { .. } => None,
        GrenSyntaxSymbol::ModuleHeaderExpose { .. } => None,
        GrenSyntaxSymbol::ModuleDocumentationAtDocsMember { .. } => None,
        GrenSyntaxSymbol::ModuleMemberDeclarationName { .. } => None,
        GrenSyntaxSymbol::ImportExpose { .. } => None,
        GrenSyntaxSymbol::LetDeclarationName { .. } => None,
        GrenSyntaxSymbol::TypeVariable { .. } => None,
        GrenSyntaxSymbol::VariableOrVariantOrOperator {
            qualification,
            name: _,
            local_bindings: _,
        }
        | GrenSyntaxSymbol::Type {
            qualification,
            name: _,
        } => {
            if implicit_imports_uniquely_qualified.iter().any(
                |&(implicit_import_qualification, _)| {
                    implicit_import_qualification == qualification
                },
            ) {
                return None;
            }
            let already_imported: bool =
                project_module_state
                    .module
                    .syntax
                    .imports
                    .iter()
                    .any(|import_node| {
                        import_node
                            .value
                            .module_name
                            .as_ref()
                            .is_some_and(|name_node| qualification == name_node.value.as_ref())
                            || import_node
                                .value
                                .alias_name
                                .as_ref()
                                .is_some_and(|alias_node| {
                                    qualification == alias_node.value.as_ref()
                                })
                    });
            if already_imported {
                return None;
            }
            Some(vec![if project_state_get_module_with_name(
                state,
                project_module_state.project,
                qualification,
            )
            .is_none()
            {
                lsp_types::CodeActionOrCommand::CodeAction(lsp_types::CodeAction {
                    title: "add missing import".to_string(),
                    kind: Some(lsp_types::CodeActionKind::QUICKFIX),
                    diagnostics: None,
                    edit: None,
                    command: None,
                    is_preferred: None,
                    disabled: Some(lsp_types::CodeActionDisabled {
                        reason: "could not find a module with this name in this project"
                            .to_string(),
                    }),
                    data: None,
                })
            } else {
                let maybe_before_import_insert_position: Option<lsp_types::Position> =
                    project_module_state
                        .module
                        .syntax
                        .imports
                        .last()
                        .map(|node| node.range.end)
                        .or_else(|| {
                            project_module_state
                                .module
                                .syntax
                                .documentation
                                .as_ref()
                                .map(|node| node.range.end)
                        })
                        .or_else(|| {
                            project_module_state
                                .module
                                .syntax
                                .header
                                .as_ref()
                                .map(gren_syntax_module_header_end_position)
                        });
                let import_insert_position = maybe_before_import_insert_position
                    .map(|end| lsp_types::Position {
                        line: end.line + 1,
                        character: 0,
                    })
                    .unwrap_or_else(|| lsp_types::Position {
                        line: 0,
                        character: 0,
                    });
                lsp_types::CodeActionOrCommand::CodeAction(lsp_types::CodeAction {
                    title: "add missing import".to_string(),
                    kind: Some(lsp_types::CodeActionKind::QUICKFIX),
                    diagnostics: None,
                    edit: Some(lsp_types::WorkspaceEdit {
                        changes: None,
                        change_annotations: None,
                        document_changes: Some(lsp_types::DocumentChanges::Edits(vec![
                            lsp_types::TextDocumentEdit {
                                text_document: lsp_types::OptionalVersionedTextDocumentIdentifier {
                                    uri: code_action_arguments.text_document.uri,
                                    version: None,
                                },
                                edits: vec![lsp_types::OneOf::Left(lsp_types::TextEdit {
                                    range: lsp_types::Range {
                                        start: import_insert_position,
                                        end: import_insert_position,
                                    },
                                    new_text: format!("import {qualification}\n"),
                                })],
                            },
                        ])),
                    }),
                    command: None,
                    is_preferred: Some(true),
                    disabled: None,
                    data: None,
                })
            }])
        }
    }
}
/// caveat: for effect modules, this does not respect the { command, subscription }
/// does not matter if you only look at lines as effect modules are currently all single-line
fn gren_syntax_module_header_end_position(
    gren_syntax_module_header: &GrenSyntaxModuleHeader,
) -> lsp_types::Position {
    gren_syntax_module_header
        .exposing
        .as_ref()
        .map(|node| node.range.end)
        .or_else(|| {
            gren_syntax_module_header
                .exposing_keyword_range
                .map(|range| range.end)
        })
        .unwrap_or_else(|| match &gren_syntax_module_header.specific {
            GrenSyntaxModuleHeaderSpecific::Pure {
                module_keyword_range,
            } => gren_syntax_module_header
                .module_name
                .as_ref()
                .map(|node| node.range.end)
                .unwrap_or(module_keyword_range.end),
            GrenSyntaxModuleHeaderSpecific::Port {
                port_keyword_range: _,
                module_keyword_range,
            } => gren_syntax_module_header
                .module_name
                .as_ref()
                .map(|node| node.range.end)
                .unwrap_or(module_keyword_range.end),
            GrenSyntaxModuleHeaderSpecific::Effect {
                effect_keyword_range: _,
                module_keyword_range: _,
                where_keyword_range,
                command: _,
                subscription: _,
            } => where_keyword_range.end,
        })
}

fn gren_make_file_problem_to_diagnostic(
    problem: &GrenMakeFileInternalCompileProblem,
) -> lsp_types::Diagnostic {
    lsp_types::Diagnostic {
        range: problem.range,
        severity: Some(lsp_types::DiagnosticSeverity::ERROR),
        code: None,
        code_description: None,
        source: None,
        message: format!("--- {} ---\n{}", &problem.title, &problem.message_markdown),
        related_information: None,
        tags: None,
        data: None,
    }
}

fn project_module_name_completions_for_except(
    state: &State,
    completion_project: &ProjectState,
    import_alias_origin_lookup: &[GrenImportAliasAndModuleOrigin],
    module_name_to_complete: &str,
    module_name_exception: Option<&str>,
) -> Vec<lsp_types::CompletionItem> {
    let module_name_base_to_complete: String = module_name_to_complete
        .rsplit_once(".")
        .map(|(before_last_dot, _)| before_last_dot.to_string() + ".")
        .unwrap_or_else(|| "".to_string());
    let to_completion_item = |module_path: &std::path::PathBuf,
                              module_name: &str,
                              module_syntax: &GrenSyntaxModule|
     -> Option<lsp_types::CompletionItem> {
        let module_url: lsp_types::Url = lsp_types::Url::from_file_path(module_path).ok()?;
        Some(lsp_types::CompletionItem {
            label: module_name.to_string(),
            insert_text: Some(
                module_name
                    .strip_prefix(&module_name_base_to_complete)
                    .unwrap_or(module_name)
                    .to_string(),
            ),
            sort_text: Some(
                module_name
                    .strip_prefix(&module_name_base_to_complete)
                    .unwrap_or(module_name)
                    .to_string(),
            ),
            kind: Some(lsp_types::CompletionItemKind::MODULE),
            documentation: Some(lsp_types::Documentation::MarkupContent(
                lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: module_syntax
                        .documentation
                        .as_ref()
                        .map(|module_documentation| {
                            gren_syntax_module_documentation_to_markdown(
                                &module_url,
                                module_syntax,
                                &module_documentation.value,
                            )
                        })
                        .unwrap_or_else(|| "_module has no documentation comment_".to_string()),
                },
            )),
            ..lsp_types::CompletionItem::default()
        })
    };
    completion_project
        .dependency_exposed_module_names
        .iter()
        .flat_map(
            |(importable_dependency_module_name, importable_dependency_module_origin)| {
                let importable_dependency_module_name_or_aliases: Vec<&str> =
                    look_up_module_origin_import_aliases(
                        import_alias_origin_lookup,
                        importable_dependency_module_name,
                    )
                    .unwrap_or_else(|| vec![importable_dependency_module_name]);
                importable_dependency_module_name_or_aliases
                    .into_iter()
                    .filter_map(|importable_dependency_module_name_or_alias| {
                        if !importable_dependency_module_name_or_alias
                            .starts_with(&module_name_base_to_complete)
                            || module_name_base_to_complete
                                .starts_with(importable_dependency_module_name_or_alias)
                        {
                            return None;
                        }
                        let importable_dependency_module_state = state
                            .projects
                            .get(&importable_dependency_module_origin.project_path)
                            .and_then(|dependency_state| {
                                dependency_state
                                    .modules
                                    .get(&importable_dependency_module_origin.module_path)
                            })?;
                        to_completion_item(
                            &importable_dependency_module_origin.module_path,
                            importable_dependency_module_name_or_alias,
                            &importable_dependency_module_state.syntax,
                        )
                    })
            },
        )
        .chain(completion_project.modules.iter().flat_map(
            |(project_module_path, project_module)| {
                project_module
                    .syntax
                    .header
                    .as_ref()
                    .and_then(|header| header.module_name.as_ref())
                    .map(|project_module_name_node| {
                        let project_module_name: &str = project_module_name_node.value.as_ref();
                        let importable_dependency_module_name_or_aliases: Vec<&str> =
                            look_up_module_origin_import_aliases(
                                import_alias_origin_lookup,
                                project_module_name,
                            )
                            .unwrap_or_else(|| vec![project_module_name]);
                        importable_dependency_module_name_or_aliases
                            .into_iter()
                            .filter_map(|importable_dependency_module_name_or_alias| {
                                if !importable_dependency_module_name_or_alias
                                    .starts_with(&module_name_base_to_complete)
                                    || module_name_base_to_complete
                                        .starts_with(importable_dependency_module_name_or_alias)
                                    || Some(importable_dependency_module_name_or_alias)
                                        == module_name_exception
                                {
                                    None
                                } else {
                                    to_completion_item(
                                        project_module_path,
                                        importable_dependency_module_name_or_alias,
                                        &project_module.syntax,
                                    )
                                }
                            })
                    })
                    .into_iter()
                    .flatten()
            },
        ))
        .collect::<Vec<_>>()
}
fn gren_syntax_module_documentation_to_markdown(
    module_url: &lsp_types::Url,
    module_syntax: &GrenSyntaxModule,
    module_documentation_elements: &[GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
) -> String {
    let all_at_docs_module_members: std::collections::HashSet<&str> = module_documentation_elements
        .iter()
        .flat_map(|module_documentation_element_node| {
            match &module_documentation_element_node.value {
                GrenSyntaxModuleDocumentationElement::Markdown(_) => None,
                GrenSyntaxModuleDocumentationElement::AtDocs(expose_group_names) => {
                    Some(expose_group_names.iter().map(|node| {
                        node.value
                            .as_ref()
                            .trim_start_matches('(')
                            .trim_end_matches(')')
                    }))
                }
            }
            .into_iter()
            .flatten()
        })
        .collect::<std::collections::HashSet<_>>();
    let module_member_declaration_names: std::collections::HashMap<&str, lsp_types::Range> =
        if all_at_docs_module_members.is_empty() {
            std::collections::HashMap::new()
        } else {
            module_syntax
                .declarations
                .iter()
                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                .filter_map(|documented| documented.declaration.as_ref())
                .filter_map(|declaration_node| match &declaration_node.value {
                    GrenSyntaxDeclaration::ChoiceType {
                        name: maybe_declaration_name,
                        ..
                    } => maybe_declaration_name
                        .as_ref()
                        .map(|node| (node.value.as_ref(), node.range)),
                    GrenSyntaxDeclaration::Operator {
                        operator: maybe_operator,
                        ..
                    } => maybe_operator.as_ref().map(|node| (node.value, node.range)),
                    GrenSyntaxDeclaration::Port {
                        name: maybe_declaration_name,
                        ..
                    } => maybe_declaration_name
                        .as_ref()
                        .map(|node| (node.value.as_ref(), node.range)),
                    GrenSyntaxDeclaration::TypeAlias {
                        name: maybe_declaration_name,
                        ..
                    } => maybe_declaration_name
                        .as_ref()
                        .map(|node| (node.value.as_ref(), node.range)),
                    GrenSyntaxDeclaration::Variable {
                        start_name: declaration_start_name_node,
                        ..
                    } => Some((
                        declaration_start_name_node.value.as_ref(),
                        declaration_start_name_node.range,
                    )),
                })
                .filter(|(name, _)| all_at_docs_module_members.contains(name))
                .collect::<std::collections::HashMap<_, _>>()
        };
    let look_up_module_member_declaration_name_range =
        |expose_name: &str| -> Option<lsp_types::Range> {
            module_member_declaration_names
                .get(expose_name.trim_start_matches('(').trim_end_matches(')'))
                .copied()
        };
    let mut result_builder: String = String::new();
    for module_documentation_element_node in module_documentation_elements {
        match &module_documentation_element_node.value {
            GrenSyntaxModuleDocumentationElement::Markdown(markdown_node) => {
                markdown_convert_code_blocks_to_gren_into(&mut result_builder, markdown_node);
            }
            GrenSyntaxModuleDocumentationElement::AtDocs(expose_group_names) => {
                // consider inlining their documentation as well
                result_builder.push_str("_see_ ");
                if let Some((expose_name_node0, expose_name1_up)) = expose_group_names.split_first()
                {
                    match look_up_module_member_declaration_name_range(
                        expose_name_node0.value.as_ref(),
                    ) {
                        None => {
                            result_builder.push_str(&expose_name_node0.value);
                        }
                        Some(module_member0_declaration_name_range) => {
                            name_as_module_module_member_markdown_link_into(
                                &mut result_builder,
                                module_url,
                                module_member0_declaration_name_range,
                                &expose_name_node0.value,
                            );
                        }
                    }
                    for expose_name_node in expose_name1_up {
                        result_builder.push_str(", ");
                        match look_up_module_member_declaration_name_range(
                            expose_name_node.value.as_ref(),
                        ) {
                            None => {
                                result_builder.push_str(&expose_name_node.value);
                            }
                            Some(module_member_declaration_name_range) => {
                                name_as_module_module_member_markdown_link_into(
                                    &mut result_builder,
                                    module_url,
                                    module_member_declaration_name_range,
                                    &expose_name_node.value,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    result_builder
}
fn name_as_module_module_member_markdown_link_into(
    builder: &mut String,
    module_url: &lsp_types::Url,
    module_member_declaration_name_range: lsp_types::Range,
    module_member_name: &str,
) {
    // I've searched a bunch but couldn't find a standardized way to link
    // to a document symbol. What is done here is only checked to work in vscode-like editors
    let expose_name_normal: &str = module_member_name
        .strip_suffix("(..)")
        .unwrap_or(module_member_name);
    builder.push_str("[`");
    builder.push_str(expose_name_normal);
    builder.push_str("`](");
    builder.push_str(module_url.as_str());
    builder.push_str("#L");
    {
        use std::fmt::Write as _;
        let _ = write!(
            builder,
            "{}",
            // at least in vscode-like editors it's 1-based
            1 + module_member_declaration_name_range.start.line
        );
    }
    builder.push(')');
}
fn documentation_comment_to_markdown(documentation: &str) -> String {
    let markdown_source: &str = documentation.trim();
    let mut builder: String = String::new();
    markdown_convert_code_blocks_to_gren_into(&mut builder, markdown_source);
    builder
}
fn markdown_convert_code_blocks_to_gren_into(builder: &mut String, markdown_source: &str) {
    // because I don't want to introduce a full markdown parser for just this tiny
    // improvement, the code below only approximates where code blocks are.
    let mut with_fenced_code_blocks_converted = String::new();
    markdown_convert_unspecific_fenced_code_blocks_to_gren_into(
        &mut with_fenced_code_blocks_converted,
        markdown_source,
    );
    markdown_convert_indented_code_blocks_to_gren(builder, &with_fenced_code_blocks_converted);
}

/// replace fenced no-language-specified code blocks by `gren...`
fn markdown_convert_unspecific_fenced_code_blocks_to_gren_into(
    result_builder: &mut String,
    markdown_source: &str,
) {
    let mut current_source_index: usize = 0;
    'converting_fenced: while current_source_index < markdown_source.len() {
        match markdown_source[current_source_index..]
            .find("```")
            .map(|i| i + current_source_index)
        {
            None => {
                result_builder.push_str(&markdown_source[current_source_index..]);
                break 'converting_fenced;
            }
            Some(index_at_opening_fence) => {
                let index_after_opening_fence = index_at_opening_fence + 3;
                match markdown_source[index_after_opening_fence..]
                    .find("```")
                    .map(|i| i + index_after_opening_fence)
                {
                    None => {
                        result_builder.push_str(&markdown_source[current_source_index..]);
                        break 'converting_fenced;
                    }
                    Some(index_at_closing_fence) => {
                        match markdown_source[index_after_opening_fence..].chars().next() {
                            // fenced block without a specific language
                            Some('\n') => {
                                result_builder.push_str(
                                    &markdown_source[current_source_index..index_at_opening_fence],
                                );
                                result_builder.push_str("```gren");
                                result_builder.push_str(
                                    &markdown_source
                                        [index_after_opening_fence..index_at_closing_fence],
                                );
                                result_builder.push_str("```");
                                current_source_index = index_at_closing_fence + 3;
                            }
                            // fenced block with a specific language
                            _ => {
                                result_builder.push_str(
                                    &markdown_source
                                        [current_source_index..(index_at_closing_fence + 3)],
                                );
                                current_source_index = index_at_closing_fence + 3;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn markdown_convert_indented_code_blocks_to_gren(builder: &mut String, markdown_source: &str) {
    let mut current_indent: usize = 0;
    let mut is_in_code_block: bool = false;
    let mut previous_line_was_blank: bool = false;
    for source_line in markdown_source.lines() {
        if source_line.is_empty() {
            builder.push('\n');
            previous_line_was_blank = true;
        } else {
            let current_line_indent: usize = source_line
                .chars()
                .take_while(char::is_ascii_whitespace)
                .count();
            if current_line_indent == source_line.len() {
                // ignore blank line
                builder.push_str(source_line);
                builder.push('\n');
                previous_line_was_blank = true;
            } else {
                if is_in_code_block {
                    if current_line_indent <= current_indent - 1 {
                        is_in_code_block = false;
                        current_indent = current_line_indent;
                        builder.push_str("```\n");
                        builder.push_str(source_line);
                        builder.push('\n');
                    } else {
                        builder.push_str(&source_line[current_indent..]);
                        builder.push('\n');
                    }
                } else if previous_line_was_blank && (current_line_indent >= current_indent + 4) {
                    is_in_code_block = true;
                    current_indent = current_line_indent;
                    builder.push_str("```gren\n");
                    builder.push_str(&source_line[current_line_indent..]);
                    builder.push('\n');
                } else {
                    current_indent = current_line_indent;
                    builder.push_str(source_line);
                    builder.push('\n');
                }
                previous_line_was_blank = false;
            }
        }
    }
    if is_in_code_block {
        builder.push_str("```\n");
    }
}

fn lsp_range_includes_position(range: lsp_types::Range, position: lsp_types::Position) -> bool {
    (
        // position >= range.start
        (position.line > range.start.line)
            || ((position.line == range.start.line)
                && (position.character >= range.start.character))
    ) && (
        // position <= range.end
        (position.line < range.end.line)
            || ((position.line == range.end.line) && (position.character <= range.end.character))
    )
}

struct PositionDelta {
    line: u32,
    character: u32,
}
fn lsp_position_positive_delta(
    before: lsp_types::Position,
    after: lsp_types::Position,
) -> Result<PositionDelta, String> {
    match before.line.cmp(&after.line) {
        std::cmp::Ordering::Greater => Err(format!(
            "before line > after line (before: {}, after {})",
            lsp_position_to_string(before),
            lsp_position_to_string(after)
        )),
        std::cmp::Ordering::Equal => {
            if before.character > after.character {
                Err(format!(
                    "before character > after character (before: {}, after {})",
                    lsp_position_to_string(before),
                    lsp_position_to_string(after)
                ))
            } else {
                Ok(PositionDelta {
                    line: 0,
                    character: after.character - before.character,
                })
            }
        }
        std::cmp::Ordering::Less => Ok(PositionDelta {
            line: after.line - before.line,
            character: after.character,
        }),
    }
}
fn lsp_position_to_string(lsp_position: lsp_types::Position) -> String {
    format!("{}:{}", lsp_position.line, lsp_position.character)
}

fn lsp_position_add_characters(
    position: lsp_types::Position,
    additional_character_count: i32,
) -> lsp_types::Position {
    lsp_types::Position {
        line: position.line,
        character: (position.character as i32 + additional_character_count) as u32,
    }
}

fn gren_syntax_highlight_kind_to_lsp_semantic_token_type(
    gren_syntax_highlight_kind: &GrenSyntaxHighlightKind,
) -> lsp_types::SemanticTokenType {
    match gren_syntax_highlight_kind {
        GrenSyntaxHighlightKind::KeySymbol => lsp_types::SemanticTokenType::KEYWORD,
        GrenSyntaxHighlightKind::Operator => lsp_types::SemanticTokenType::OPERATOR,
        GrenSyntaxHighlightKind::Field => lsp_types::SemanticTokenType::PROPERTY,
        GrenSyntaxHighlightKind::ModuleNameOrAlias => lsp_types::SemanticTokenType::NAMESPACE,
        GrenSyntaxHighlightKind::Type => lsp_types::SemanticTokenType::TYPE,
        GrenSyntaxHighlightKind::Variable => lsp_types::SemanticTokenType::VARIABLE,
        GrenSyntaxHighlightKind::Variant => lsp_types::SemanticTokenType::ENUM_MEMBER,
        GrenSyntaxHighlightKind::DeclaredVariable => lsp_types::SemanticTokenType::FUNCTION,
        GrenSyntaxHighlightKind::Comment => lsp_types::SemanticTokenType::COMMENT,
        GrenSyntaxHighlightKind::Number => lsp_types::SemanticTokenType::NUMBER,
        GrenSyntaxHighlightKind::String => lsp_types::SemanticTokenType::STRING,
        GrenSyntaxHighlightKind::TypeVariable => lsp_types::SemanticTokenType::TYPE_PARAMETER,
    }
}

fn derive_module_name_from_path(
    source_directories: &[std::path::PathBuf],
    module_path: &std::path::Path,
) -> Option<String> {
    source_directories
        .iter()
        .filter_map(|source_directory_path| module_path.strip_prefix(source_directory_path).ok())
        .filter_map(std::path::Path::to_str)
        .max_by(|a, b| a.len().cmp(&b.len()))
        .map(|path_in_source_directory| {
            path_in_source_directory
                // I'm certain there is a better way to convert path separators independent of OS
                .trim_start_matches(['/', '\\'])
                .trim_end_matches(".gren")
                .replace(['/', '\\'], ".")
        })
}

fn list_gren_files_in_directory_at_paths(
    paths: impl Iterator<Item = std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut result: Vec<std::path::PathBuf> = Vec::new();
    for path in paths {
        list_files_passing_test_in_directory_at_path_into(&mut result, path, |file_path| {
            file_path
                .extension()
                .is_some_and(|extension| extension == "gren")
        });
    }
    result
}

fn list_gren_project_directories_in_directory_at_path(
    paths: impl Iterator<Item = std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut result: Vec<std::path::PathBuf> = Vec::new();
    for path in paths {
        list_gren_project_directories_in_directory_at_path_into(&mut result, &path);
    }
    result
}

fn list_gren_project_directories_in_directory_at_path_into(
    so_far: &mut Vec<std::path::PathBuf>,
    path: &std::path::PathBuf,
) {
    if !path.is_dir() {
        return;
    }
    if path
        .file_name()
        .is_some_and(|file_name| file_name == ".gren")
    {
        // some gren tools put generated code including gren.json there
        return;
    }
    if let Ok(dir_subs) = std::fs::read_dir(path) {
        for dir_sub in dir_subs.into_iter().filter_map(Result::ok) {
            let dir_sub_path: std::path::PathBuf = dir_sub.path();
            if dir_sub_path.is_file()
                && dir_sub_path
                    .file_name()
                    .is_some_and(|file_name| file_name == "gren.json")
            {
                so_far.push(path.clone());
            }
            list_gren_project_directories_in_directory_at_path_into(so_far, &dir_sub_path);
        }
    }
}

fn list_files_passing_test_in_directory_at_path_into(
    so_far: &mut Vec<std::path::PathBuf>,
    path: std::path::PathBuf,
    should_add_file: fn(&std::path::PathBuf) -> bool,
) {
    if path.is_dir() {
        if let Ok(dir_subs) = std::fs::read_dir(&path) {
            for dir_sub in dir_subs.into_iter().filter_map(Result::ok) {
                list_files_passing_test_in_directory_at_path_into(
                    so_far,
                    dir_sub.path(),
                    should_add_file,
                );
            }
        }
    } else {
        if should_add_file(&path) {
            so_far.push(path);
        }
    }
}

// // // below persistent rust types and conversions to and from temporary gren types
#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxType {
    Variable(Box<str>),
    Parenthesized(Option<GrenSyntaxNode<Box<GrenSyntaxType>>>),
    Function {
        input: GrenSyntaxNode<Box<GrenSyntaxType>>,
        arrow_key_symbol_range: lsp_types::Range,
        output: Option<GrenSyntaxNode<Box<GrenSyntaxType>>>,
    },
    Construct {
        reference: GrenSyntaxNode<GrenQualifiedName>,
        arguments: Vec<GrenSyntaxNode<GrenSyntaxType>>,
    },
    Record(Vec<GrenSyntaxTypeField>),
    RecordExtension {
        record_variable: Option<GrenSyntaxNode<Box<str>>>,
        bar_key_symbol_range: lsp_types::Range,
        fields: Vec<GrenSyntaxTypeField>,
    },
}
#[derive(Clone, Debug, PartialEq)]
struct GrenQualifiedName {
    qualification: Box<str>,
    name: Box<str>,
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxTypeField {
    name: GrenSyntaxNode<Box<str>>,
    colon_key_symbol_range: Option<lsp_types::Range>,
    value: Option<GrenSyntaxNode<GrenSyntaxType>>,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxPattern {
    Ignored(Option<Box<str>>),
    Char(Option<char>),
    Int {
        base: GrenSyntaxIntBase,
        value: Result<i64, Box<str>>,
    },
    String {
        content: String,
        quoting_style: GrenSyntaxStringQuotingStyle,
    },
    Variable(Box<str>),
    As {
        pattern: GrenSyntaxNode<Box<GrenSyntaxPattern>>,
        as_keyword_range: lsp_types::Range,
        variable: Option<GrenSyntaxNode<Box<str>>>,
    },
    Parenthesized(Option<GrenSyntaxNode<Box<GrenSyntaxPattern>>>),
    Record(Vec<GrenSyntaxPatternField>),
    Variant {
        reference: GrenSyntaxNode<GrenQualifiedName>,
        value: Option<GrenSyntaxNode<Box<GrenSyntaxPattern>>>,
    },
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxPatternField {
    name: GrenSyntaxNode<Box<str>>,
    equals_key_symbol_range: Option<lsp_types::Range>,
    value: Option<GrenSyntaxNode<GrenSyntaxPattern>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrenSyntaxStringQuotingStyle {
    SingleQuoted,
    TripleQuoted,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxModuleHeaderSpecific {
    // if you have a better name for this, please tell me
    Pure {
        module_keyword_range: lsp_types::Range,
    },
    Port {
        port_keyword_range: lsp_types::Range,
        module_keyword_range: lsp_types::Range,
    },
    Effect {
        effect_keyword_range: lsp_types::Range,
        module_keyword_range: lsp_types::Range,
        where_keyword_range: lsp_types::Range,
        command: Option<EffectModuleHeaderEntry>,
        subscription: Option<EffectModuleHeaderEntry>,
    },
}
#[derive(Clone, Debug, PartialEq)]
struct EffectModuleHeaderEntry {
    key_range: lsp_types::Range,
    equals_range: lsp_types::Range,
    value_type_name: GrenSyntaxNode<Box<str>>,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxLetDeclaration {
    Destructuring {
        pattern: GrenSyntaxNode<GrenSyntaxPattern>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        expression: Option<GrenSyntaxNode<GrenSyntaxExpression>>,
    },
    VariableDeclaration {
        start_name: GrenSyntaxNode<Box<str>>,
        signature: Option<GrenSyntaxVariableDeclarationSignature>,
        parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        result: Option<GrenSyntaxNode<GrenSyntaxExpression>>,
    },
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxVariableDeclarationSignature {
    colon_key_symbol_range: lsp_types::Range,
    type_: Option<GrenSyntaxNode<GrenSyntaxType>>,
    implementation_name_range: Option<lsp_types::Range>,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxExpression {
    Call {
        called: GrenSyntaxNode<Box<GrenSyntaxExpression>>,
        argument0: GrenSyntaxNode<Box<GrenSyntaxExpression>>,
        argument1_up: Vec<GrenSyntaxNode<GrenSyntaxExpression>>,
    },
    CaseOf {
        matched: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
        of_keyword_range: Option<lsp_types::Range>,
        cases: Vec<GrenSyntaxExpressionCase>,
    },
    Char(Option<char>),
    Float(Result<f64, Box<str>>),
    IfThenElse {
        condition: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
        then_keyword_range: Option<lsp_types::Range>,
        on_true: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
        else_keyword_range: Option<lsp_types::Range>,
        on_false: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
    },
    /// gren-syntax for example uses a pratt parser
    /// to produce the actual, semantically correct tree as you would evaluate it.
    /// However, such a tree is irrelevant
    /// for the existing functionality of the language server,
    /// so we instead simply parse it "left, grouping right". For example:
    ///
    ///     3 + 4 * 5 - 6
    ///
    /// in gren-syntax:
    ///
    ///     Op (Op 3 "+" (Op 4 "*" 5)) "-" 6
    ///
    /// here:
    ///
    ///     Op 3 "+" (Op 4 "*" (Op 5 "-" 6))
    InfixOperationIgnoringPrecedence {
        left: GrenSyntaxNode<Box<GrenSyntaxExpression>>,
        operator: GrenSyntaxNode<&'static str>,
        right: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
    },
    Integer {
        base: GrenSyntaxIntBase,
        value: Result<i64, Box<str>>,
    },
    Lambda {
        parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>>,
        arrow_key_symbol_range: Option<lsp_types::Range>,
        result: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
    },
    LetIn {
        declarations: Vec<GrenSyntaxNode<GrenSyntaxLetDeclaration>>,
        in_keyword_range: Option<lsp_types::Range>,
        result: Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>,
    },
    Array(Vec<GrenSyntaxNode<GrenSyntaxExpression>>),
    Negation(Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>),
    OperatorFunction(GrenSyntaxNode<&'static str>),
    Parenthesized(Option<GrenSyntaxNode<Box<GrenSyntaxExpression>>>),
    Record(Vec<GrenSyntaxExpressionField>),
    RecordAccess {
        record: GrenSyntaxNode<Box<GrenSyntaxExpression>>,
        field: Option<GrenSyntaxNode<Box<str>>>,
    },
    RecordAccessFunction(Option<GrenSyntaxNode<Box<str>>>),
    RecordUpdate {
        record_variable: Option<GrenSyntaxNode<Box<str>>>,
        bar_key_symbol_range: lsp_types::Range,
        fields: Vec<GrenSyntaxExpressionField>,
    },
    Reference {
        qualification: Box<str>,
        name: Box<str>,
    },
    String {
        content: String,
        quoting_style: GrenSyntaxStringQuotingStyle,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrenSyntaxIntBase {
    IntBase10,
    IntBase16,
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxExpressionCase {
    arrow_key_symbol_range: Option<lsp_types::Range>,
    pattern: GrenSyntaxNode<GrenSyntaxPattern>,
    result: Option<GrenSyntaxNode<GrenSyntaxExpression>>,
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxExpressionField {
    name: GrenSyntaxNode<Box<str>>,
    equals_key_symbol_range: Option<lsp_types::Range>,
    value: Option<GrenSyntaxNode<GrenSyntaxExpression>>,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxExposing {
    All(lsp_types::Range),
    Explicit(Vec<GrenSyntaxNode<GrenSyntaxExpose>>),
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxExpose {
    ChoiceTypeIncludingVariants {
        name: GrenSyntaxNode<Box<str>>,
        open_range: Option<lsp_types::Range>,
    },
    Operator(Option<GrenSyntaxNode<&'static str>>),
    Type(Box<str>),
    Variable(Box<str>),
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxDeclaration {
    ChoiceType {
        name: Option<GrenSyntaxNode<Box<str>>>,
        parameters: Vec<GrenSyntaxNode<Box<str>>>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        variant0_name: Option<GrenSyntaxNode<Box<str>>>,
        variant0_value: Option<GrenSyntaxNode<GrenSyntaxType>>,
        variant1_up: Vec<GrenSyntaxChoiceTypeDeclarationTailingVariant>,
    },
    Operator {
        direction: Option<GrenSyntaxNode<GrenSyntaxInfixDirection>>,
        precedence: Option<GrenSyntaxNode<i64>>,
        operator: Option<GrenSyntaxNode<&'static str>>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        function: Option<GrenSyntaxNode<Box<str>>>,
    },
    Port {
        name: Option<GrenSyntaxNode<Box<str>>>,
        colon_key_symbol_range: Option<lsp_types::Range>,
        type_: Option<GrenSyntaxNode<GrenSyntaxType>>,
    },
    TypeAlias {
        alias_keyword_range: lsp_types::Range,
        name: Option<GrenSyntaxNode<Box<str>>>,
        parameters: Vec<GrenSyntaxNode<Box<str>>>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        type_: Option<GrenSyntaxNode<GrenSyntaxType>>,
    },
    Variable {
        start_name: GrenSyntaxNode<Box<str>>,
        signature: Option<GrenSyntaxVariableDeclarationSignature>,
        parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>>,
        equals_key_symbol_range: Option<lsp_types::Range>,
        result: Option<GrenSyntaxNode<GrenSyntaxExpression>>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrenSyntaxInfixDirection {
    Left,
    Non,
    Right,
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxChoiceTypeDeclarationTailingVariant {
    or_key_symbol_range: lsp_types::Range,
    name: Option<GrenSyntaxNode<Box<str>>>,
    value: Option<GrenSyntaxNode<GrenSyntaxType>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct GrenSyntaxNode<Value> {
    range: lsp_types::Range,
    value: Value,
}

fn gren_syntax_node_as_ref<Value>(
    gren_syntax_node: &GrenSyntaxNode<Value>,
) -> GrenSyntaxNode<&Value> {
    GrenSyntaxNode {
        range: gren_syntax_node.range,
        value: &gren_syntax_node.value,
    }
}
fn gren_syntax_node_as_ref_map<'a, A, B>(
    gren_syntax_node: &'a GrenSyntaxNode<A>,
    value_change: impl Fn(&'a A) -> B,
) -> GrenSyntaxNode<B> {
    GrenSyntaxNode {
        range: gren_syntax_node.range,
        value: value_change(&gren_syntax_node.value),
    }
}
fn gren_syntax_node_map<A, B>(
    gren_syntax_node: GrenSyntaxNode<A>,
    value_change: impl Fn(A) -> B,
) -> GrenSyntaxNode<B> {
    GrenSyntaxNode {
        range: gren_syntax_node.range,
        value: value_change(gren_syntax_node.value),
    }
}
fn gren_syntax_node_unbox<Value: ?Sized>(
    gren_syntax_node_box: &GrenSyntaxNode<Box<Value>>,
) -> GrenSyntaxNode<&Value> {
    GrenSyntaxNode {
        range: gren_syntax_node_box.range,
        value: &gren_syntax_node_box.value,
    }
}
fn gren_syntax_node_box<Value>(
    gren_syntax_node_box: GrenSyntaxNode<Value>,
) -> GrenSyntaxNode<Box<Value>> {
    GrenSyntaxNode {
        range: gren_syntax_node_box.range,
        value: Box::new(gren_syntax_node_box.value),
    }
}

#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxModuleHeader {
    specific: GrenSyntaxModuleHeaderSpecific,
    module_name: Option<GrenSyntaxNode<Box<str>>>,
    exposing_keyword_range: Option<lsp_types::Range>,
    exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>>,
}

#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxModule {
    header: Option<GrenSyntaxModuleHeader>,
    documentation:
        Option<GrenSyntaxNode<Vec<GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>>>>,
    imports: Vec<GrenSyntaxNode<GrenSyntaxImport>>,
    comments: Vec<GrenSyntaxNode<GrenSyntaxComment>>,
    declarations: Vec<Result<GrenSyntaxDocumentedDeclaration, Box<str>>>,
}

#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxModuleDocumentationElement {
    Markdown(Box<str>),
    AtDocs(Vec<GrenSyntaxNode<Box<str>>>),
}

#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxDocumentedDeclaration {
    documentation: Option<GrenSyntaxNode<Box<str>>>,
    declaration: Option<GrenSyntaxNode<GrenSyntaxDeclaration>>,
}

#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxImport {
    module_name: Option<GrenSyntaxNode<Box<str>>>,
    as_keyword_range: Option<lsp_types::Range>,
    alias_name: Option<GrenSyntaxNode<Box<str>>>,
    exposing_keyword_range: Option<lsp_types::Range>,
    exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>>,
}
#[derive(Clone, Debug)]
enum GrenExposeSet<'a> {
    All,
    Explicit {
        operators: Vec<&'a str>,
        variables: Vec<&'a str>,
        types: Vec<&'a str>,
        choice_types_including_variants: Vec<&'a str>,
    },
}
fn gren_syntax_module_header_expose_set<'a>(
    gren_syntax_module_header: Option<&'a GrenSyntaxModuleHeader>,
) -> GrenExposeSet<'a> {
    match gren_syntax_module_header.and_then(|header| header.exposing.as_ref()) {
        None => GrenExposeSet::All,
        Some(module_header_expose_specific_node) => {
            gren_syntax_exposing_to_set(&module_header_expose_specific_node.value)
        }
    }
}
fn gren_syntax_exposing_to_set<'a>(
    gren_syntax_exposing: &'a GrenSyntaxExposing,
) -> GrenExposeSet<'a> {
    match gren_syntax_exposing {
        GrenSyntaxExposing::All(_) => GrenExposeSet::All,
        GrenSyntaxExposing::Explicit(exposes) => {
            let mut operators: Vec<&str> = Vec::new();
            let mut variables: Vec<&str> = Vec::with_capacity(exposes.len());
            let mut types: Vec<&str> = Vec::new();
            let mut choice_types_including_variants: Vec<&str> = Vec::new();
            for expose_node in exposes {
                match &expose_node.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name: name_node,
                        open_range: _,
                    } => {
                        choice_types_including_variants.push(&name_node.value);
                    }
                    GrenSyntaxExpose::Operator(None) => {}
                    GrenSyntaxExpose::Operator(Some(operator_node)) => {
                        operators.push(operator_node.value);
                    }
                    GrenSyntaxExpose::Type(name) => {
                        types.push(name);
                    }
                    GrenSyntaxExpose::Variable(name) => {
                        variables.push(name);
                    }
                }
            }
            GrenExposeSet::Explicit {
                operators: operators,
                variables: variables,
                types: types,
                choice_types_including_variants: choice_types_including_variants,
            }
        }
    }
}
fn gren_expose_set_contains_type(expose_set: &GrenExposeSet, name_to_check: &str) -> bool {
    match expose_set {
        GrenExposeSet::All => true,
        GrenExposeSet::Explicit {
            choice_types_including_variants,
            types,
            operators: _,
            variables: _,
        } => {
            types.contains(&name_to_check)
                || choice_types_including_variants.contains(&name_to_check)
        }
    }
}
fn gren_expose_set_contains_type_not_including_variants(
    expose_set: &GrenExposeSet,
    name_to_check: &str,
) -> bool {
    match expose_set {
        GrenExposeSet::All => true,
        GrenExposeSet::Explicit {
            choice_types_including_variants: _,
            types,
            operators: _,
            variables: _,
        } => types.contains(&name_to_check),
    }
}
fn gren_expose_set_contains_variable(expose_set: &GrenExposeSet, name_to_check: &str) -> bool {
    match expose_set {
        GrenExposeSet::All => true,
        GrenExposeSet::Explicit {
            choice_types_including_variants: _,
            types: _,
            operators: _,
            variables,
        } => variables.contains(&name_to_check),
    }
}
fn gren_expose_set_contains_choice_type_including_variants(
    expose_set: &GrenExposeSet,
    name_to_check: &str,
) -> bool {
    match expose_set {
        GrenExposeSet::All => true,
        GrenExposeSet::Explicit {
            choice_types_including_variants,
            types: _,
            operators: _,
            variables: _,
        } => choice_types_including_variants.contains(&name_to_check),
    }
}
fn gren_expose_set_contains(expose_set: &GrenExposeSet, name_to_check: &str) -> bool {
    match expose_set {
        GrenExposeSet::All => true,
        GrenExposeSet::Explicit {
            operators,
            variables,
            types,
            choice_types_including_variants,
        } => {
            operators.contains(&name_to_check)
                || variables.contains(&name_to_check)
                || types.contains(&name_to_check)
                || choice_types_including_variants.contains(&name_to_check)
        }
    }
}

/// Create through `module_origin_lookup_for_implicit_imports` or
/// `gren_syntax_module_create_origin_lookup`
struct ModuleOriginLookup<'a> {
    unqualified: std::collections::HashMap<&'a str, &'a str>,
    uniquely_qualified: std::collections::HashMap<&'a str, &'a str>,
    // in theory, uniquely_qualified and ambiguously_qualified can be combined into a
    // unified map from qualified to origin module.
    //
    // Issue is that a ModuleOriginLookup should be cheap to construct (creating an
    // entry for every member of every imported module and always looking up by
    // qualification+name pair can get somewhat expensive) and so, because
    // qualifications are rarely ambiguous in practice, we split these into the
    // common, cheap and rare, expensive parts
    ambiguously_qualified: std::collections::HashMap<GrenQualified<'a>, &'a str>,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct GrenQualified<'a> {
    qualification: &'a str,
    name: &'a str,
}

fn module_origin_lookup_for_implicit_imports() -> ModuleOriginLookup<'static> {
    // https://github.com/gren-lang/core?tab=readme-ov-file#default-imports
    ModuleOriginLookup {
        unqualified: std::collections::HashMap::from([
            ("Int", "Basics"),
            ("Float", "Basics"),
            ("+", "Basics"),
            ("-", "Basics"),
            ("*", "Basics"),
            ("/", "Basics"),
            ("//", "Basics"),
            ("^", "Basics"),
            ("toFloat", "Basics"),
            ("==", "Basics"),
            ("!=", "Basics"),
            ("<", "Basics"),
            (">", "Basics"),
            ("<=", "Basics"),
            (">=", "Basics"),
            ("max", "Basics"),
            ("min", "Basics"),
            ("compare", "Basics"),
            ("Order", "Basics"),
            ("LT", "Basics"),
            ("EQ", "Basics"),
            ("GT", "Basics"),
            ("Bool", "Basics"),
            ("True", "Basics"),
            ("False", "Basics"),
            ("not", "Basics"),
            ("&&", "Basics"),
            ("||", "Basics"),
            ("xor", "Basics"),
            ("++", "Basics"),
            ("negate", "Basics"),
            ("clamp", "Basics"),
            ("isNaN", "Basics"),
            ("isInfinite", "Basics"),
            ("identity", "Basics"),
            ("<|", "Basics"),
            ("|>", "Basics"),
            ("<<", "Basics"),
            (">>", "Basics"),
            ("Never", "Basics"),
            ("never", "Basics"),
            ("Array", "Array"),
            ("Maybe", "Maybe"),
            ("Just", "Maybe"),
            ("Nothing", "Maybe"),
            ("Result", "Result"),
            ("Ok", "Result"),
            ("Err", "Result"),
            ("String", "String"),
            ("Char", "Char"),
            ("Program", "Platform"),
            ("Cmd", "Platform.Cmd"),
            ("Sub", "Platform.Sub"),
        ]),
        uniquely_qualified: std::collections::HashMap::from(implicit_imports_uniquely_qualified),
        ambiguously_qualified: std::collections::HashMap::new(),
    }
}
const implicit_imports_uniquely_qualified: [(&str, &str); 10] = [
    ("Basics", "Basics"),
    ("Array", "Array"),
    ("Maybe", "Maybe"),
    ("Result", "Result"),
    ("String", "String"),
    ("Char", "Char"),
    ("Debug", "Debug"),
    ("Platform", "Platform"),
    ("Cmd", "Platform.Cmd"),
    ("Sub", "Platform.Sub"),
];

fn look_up_origin_module<'a>(
    module_origin_lookup: &ModuleOriginLookup<'a>,
    qualified: GrenQualified<'a>,
) -> &'a str {
    match match qualified.qualification {
        "" => module_origin_lookup.unqualified.get(qualified.name),
        qualification_module_or_alias => module_origin_lookup
            .uniquely_qualified
            .get(qualification_module_or_alias),
    } {
        Some(module_origin) => module_origin,
        None => match module_origin_lookup.ambiguously_qualified.get(&qualified) {
            Some(module_origin) => module_origin,
            None => qualified.qualification,
        },
    }
}
#[derive(Clone, Copy, Debug)]
struct GrenImportAliasAndModuleOrigin<'a> {
    alias: &'a str,
    module_origin: &'a str,
}
fn gren_syntax_imports_create_import_alias_origin_lookup<'a>(
    gren_syntax_imports: &'a [GrenSyntaxNode<GrenSyntaxImport>],
) -> Vec<GrenImportAliasAndModuleOrigin<'a>> {
    gren_syntax_imports
        .iter()
        .filter_map(|import_node| {
            let module_origin_node = import_node.value.module_name.as_ref()?;
            let alias_name_node = import_node.value.alias_name.as_ref()?;
            Some(GrenImportAliasAndModuleOrigin {
                module_origin: &module_origin_node.value,
                alias: &alias_name_node.value,
            })
        })
        .collect::<Vec<_>>()
}
fn look_up_import_alias_module_origins<'a>(
    import_alias_origin_lookup: &[GrenImportAliasAndModuleOrigin<'a>],
    alias_to_collect_origins_for: &str,
) -> Option<Vec<&'a str>> {
    let module_origins = import_alias_origin_lookup
        .iter()
        .filter_map(move |alias_and_module_origin| {
            if alias_and_module_origin.alias == alias_to_collect_origins_for {
                Some(alias_and_module_origin.module_origin)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if module_origins.is_empty() {
        None
    } else {
        Some(module_origins)
    }
}
fn look_up_module_origin_import_aliases<'a>(
    import_alias_origin_lookup: &[GrenImportAliasAndModuleOrigin<'a>],
    module_to_collect_aliases_for: &str,
) -> Option<Vec<&'a str>> {
    let module_origins = import_alias_origin_lookup
        .iter()
        .filter_map(move |alias_and_module_origin| {
            if alias_and_module_origin.module_origin == module_to_collect_aliases_for {
                Some(alias_and_module_origin.alias)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if module_origins.is_empty() {
        None
    } else {
        Some(module_origins)
    }
}

fn gren_syntax_module_create_origin_lookup<'a>(
    state: &'a State,
    project_state: &'a ProjectState,
    gren_syntax_module: &'a GrenSyntaxModule,
) -> ModuleOriginLookup<'a> {
    let mut module_origin_lookup: ModuleOriginLookup = module_origin_lookup_for_implicit_imports();
    let self_module_name: &str = match gren_syntax_module
        .header
        .as_ref()
        .and_then(|header| header.module_name.as_ref())
    {
        None => "",
        Some(module_header) => &module_header.value,
    };
    for declaration_node in gren_syntax_module
        .declarations
        .iter()
        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
        .filter_map(|documented_declaration| documented_declaration.declaration.as_ref())
    {
        match &declaration_node.value {
            GrenSyntaxDeclaration::ChoiceType {
                name: maybe_name,
                parameters: _,
                equals_key_symbol_range: _,
                variant0_name: maybe_variant0_name,
                variant0_value: _,
                variant1_up,
            } => {
                if let Some(name_node) = maybe_name {
                    module_origin_lookup
                        .unqualified
                        .insert(&name_node.value, self_module_name);
                }
                if let Some(variant0_name_node) = maybe_variant0_name {
                    module_origin_lookup
                        .unqualified
                        .insert(&variant0_name_node.value, self_module_name);
                }
                for variant in variant1_up.iter() {
                    if let Some(variant_name_node) = variant.name.as_ref() {
                        module_origin_lookup
                            .unqualified
                            .insert(&variant_name_node.value, self_module_name);
                    }
                }
            }
            GrenSyntaxDeclaration::Operator {
                direction: _,
                precedence: _,
                equals_key_symbol_range: _,
                operator: maybe_operator,
                function: _,
            } => {
                if let Some(operator_node) = maybe_operator {
                    module_origin_lookup
                        .unqualified
                        .insert(operator_node.value, self_module_name);
                }
            }
            GrenSyntaxDeclaration::Port {
                name: maybe_name,
                colon_key_symbol_range: _,
                type_: _,
            } => {
                if let Some(name_node) = maybe_name {
                    module_origin_lookup
                        .unqualified
                        .insert(&name_node.value, self_module_name);
                }
            }
            GrenSyntaxDeclaration::TypeAlias {
                alias_keyword_range: _,
                equals_key_symbol_range: _,
                name: maybe_name,
                parameters: _,
                type_: _,
            } => {
                if let Some(name_node) = maybe_name {
                    module_origin_lookup
                        .unqualified
                        .insert(&name_node.value, self_module_name);
                }
            }
            GrenSyntaxDeclaration::Variable {
                start_name: start_name_node,
                signature: _,
                parameters: _,
                equals_key_symbol_range: _,
                result: _,
            } => {
                module_origin_lookup
                    .unqualified
                    .insert(&start_name_node.value, self_module_name);
            }
        }
    }
    for (import_module_name, import) in
        gren_syntax_module.imports.iter().filter_map(|import_node| {
            import_node
                .value
                .module_name
                .as_ref()
                .map(|module_name| (&module_name.value, &import_node.value))
        })
    {
        let allowed_qualification: &str = match &import.alias_name {
            None => import_module_name,
            Some(import_alias_name) => &import_alias_name.value,
        };
        match module_origin_lookup
            .uniquely_qualified
            .remove(allowed_qualification)
        {
            None => {
                module_origin_lookup
                    .uniquely_qualified
                    .insert(allowed_qualification, import_module_name);
            }
            Some(module_origin_for_existing_qualification) => {
                if let Some((_, origin_module_state_for_existing_qualification)) =
                    project_state_get_module_with_name(
                        state,
                        project_state,
                        module_origin_for_existing_qualification,
                    )
                {
                    for imported_module_expose in gren_syntax_module_exposed_symbols(
                        &origin_module_state_for_existing_qualification.syntax,
                    ) {
                        module_origin_lookup.ambiguously_qualified.insert(
                            GrenQualified {
                                qualification: allowed_qualification,
                                name: imported_module_expose,
                            },
                            module_origin_for_existing_qualification,
                        );
                    }
                }
                if let Some((_, imported_module_state)) =
                    project_state_get_module_with_name(state, project_state, import_module_name)
                {
                    for imported_module_expose in
                        gren_syntax_module_exposed_symbols(&imported_module_state.syntax)
                    {
                        module_origin_lookup.ambiguously_qualified.insert(
                            GrenQualified {
                                qualification: allowed_qualification,
                                name: imported_module_expose,
                            },
                            import_module_name,
                        );
                    }
                }
            }
        }
        let mut insert_import_expose = |import_expose: &'a str| {
            if module_origin_lookup.unqualified.contains_key(import_expose) {
                module_origin_lookup.ambiguously_qualified.insert(
                    GrenQualified {
                        qualification: allowed_qualification,
                        name: import_expose,
                    },
                    import_module_name,
                );
            } else {
                module_origin_lookup
                    .unqualified
                    .insert(import_expose, import_module_name);
            }
        };
        if let Some(import_exposing) = &import.exposing {
            match &import_exposing.value {
                GrenSyntaxExposing::All(_) => {
                    if let Some((_, imported_module_state)) =
                        project_state_get_module_with_name(state, project_state, import_module_name)
                    {
                        for import_exposed_symbol in
                            gren_syntax_module_exposed_symbols(&imported_module_state.syntax)
                        {
                            insert_import_expose(import_exposed_symbol);
                        }
                    }
                }
                GrenSyntaxExposing::Explicit(exposes) => {
                    for expose_node in exposes {
                        match &expose_node.value {
                            GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                                name: choice_type_expose_name,
                                open_range: _,
                            } => {
                                insert_import_expose(&choice_type_expose_name.value);
                                if let Some((_, imported_module_syntax)) =
                                    project_state_get_module_with_name(
                                        state,
                                        project_state,
                                        import_module_name,
                                    )
                                {
                                    'until_origin_choice_type_declaration_found: for documented_declaration in
                                        imported_module_syntax
                                            .syntax
                                            .declarations
                                            .iter()
                                            .filter_map(|declaration_or_err| {
                                                declaration_or_err.as_ref().ok()
                                            })
                                    {
                                        if let Some(declaration_node) =
                                            &documented_declaration.declaration
                                            && let GrenSyntaxDeclaration::ChoiceType {
                                                name: maybe_imported_module_choice_type_name,
                                                parameters: _,
                                                equals_key_symbol_range: _,
                                                variant0_name:
                                                    maybe_imported_module_choice_type_variant0_name,
                                                variant0_value: _,
                                                variant1_up: imported_module_choice_type_variant1_up,
                                            } = &declaration_node.value
                                            && Some(choice_type_expose_name.value.as_ref())
                                                == maybe_imported_module_choice_type_name
                                                    .as_ref()
                                                    .map(|node| node.value.as_ref())
                                        {
                                            if let Some(
                                                imported_module_choice_type_variant0_name_node,
                                            ) = maybe_imported_module_choice_type_variant0_name
                                                .as_ref()
                                            {
                                                insert_import_expose(
                                                    &imported_module_choice_type_variant0_name_node
                                                        .value,
                                                );
                                            }
                                            for imported_module_choice_type_variant in
                                                imported_module_choice_type_variant1_up
                                            {
                                                if let Some(
                                                    imported_module_choice_type_variant_name_node,
                                                ) = imported_module_choice_type_variant
                                                    .name
                                                    .as_ref()
                                                {
                                                    insert_import_expose(
                                                            &imported_module_choice_type_variant_name_node.value,
                                                        );
                                                }
                                            }
                                            break 'until_origin_choice_type_declaration_found;
                                        }
                                    }
                                }
                            }
                            GrenSyntaxExpose::Operator(symbol) => {
                                if let Some(operator_symbol_node) = symbol {
                                    insert_import_expose(operator_symbol_node.value);
                                }
                            }
                            GrenSyntaxExpose::Type(name) => {
                                insert_import_expose(name);
                            }
                            GrenSyntaxExpose::Variable(name) => {
                                insert_import_expose(name);
                            }
                        }
                    }
                }
            }
        }
    }
    module_origin_lookup
}

fn gren_syntax_module_exposed_symbols(gren_syntax_module: &GrenSyntaxModule) -> Vec<&str> {
    match gren_syntax_module
        .header
        .as_ref()
        .and_then(|header| header.exposing.as_ref())
        .as_ref()
        .map(|node| &node.value)
    {
        None | Some(GrenSyntaxExposing::All(_)) => {
            let mut exposed_symbols: Vec<&str> =
                Vec::with_capacity(gren_syntax_module.declarations.len());
            for declaration_node in gren_syntax_module
                .declarations
                .iter()
                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                .filter_map(|documented_declaration| documented_declaration.declaration.as_ref())
            {
                match &declaration_node.value {
                    GrenSyntaxDeclaration::ChoiceType {
                        name: maybe_exposed_choice_type_name,
                        variant0_name: maybe_exposed_choice_type_variant0_name,
                        variant1_up: exposed_choice_type_variant1_up,
                        ..
                    } => {
                        if let Some(exposed_choice_type_name_node) = maybe_exposed_choice_type_name
                        {
                            exposed_symbols.push(&exposed_choice_type_name_node.value);
                        }
                        if let Some(exposed_choice_type_variant0_name_node) =
                            maybe_exposed_choice_type_variant0_name
                        {
                            exposed_symbols.push(&exposed_choice_type_variant0_name_node.value);
                        }
                        for exposed_choice_type_variant in exposed_choice_type_variant1_up {
                            if let Some(exposed_choice_type_variant_name_node) =
                                &exposed_choice_type_variant.name
                            {
                                exposed_symbols.push(&exposed_choice_type_variant_name_node.value);
                            }
                        }
                    }
                    GrenSyntaxDeclaration::Port {
                        name: maybe_exposed_port_name,
                        ..
                    } => {
                        if let Some(exposed_port_name_node) = maybe_exposed_port_name {
                            exposed_symbols.push(&exposed_port_name_node.value);
                        }
                    }
                    GrenSyntaxDeclaration::TypeAlias {
                        name: maybe_exposed_type_alias_name,
                        ..
                    } => {
                        if let Some(exposed_type_alias_name_node) = maybe_exposed_type_alias_name {
                            exposed_symbols.push(&exposed_type_alias_name_node.value);
                        }
                    }
                    GrenSyntaxDeclaration::Operator {
                        operator: maybe_exposed_operator,
                        ..
                    } => {
                        if let Some(exposed_operator_node) = maybe_exposed_operator {
                            exposed_symbols.push(exposed_operator_node.value);
                        }
                    }
                    GrenSyntaxDeclaration::Variable {
                        start_name: exposed_variable_name_node,
                        ..
                    } => {
                        exposed_symbols.push(&exposed_variable_name_node.value);
                    }
                }
            }
            exposed_symbols
        }
        Some(GrenSyntaxExposing::Explicit(exposes)) => {
            let mut exposed_symbols: Vec<&str> = Vec::with_capacity(exposes.len());
            for expose in exposes {
                match &expose.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name: choice_type_expose_name,
                        open_range: _,
                    } => {
                        exposed_symbols.push(&choice_type_expose_name.value);
                        'until_origin_choice_type_declaration_found: for declaration_node in
                            gren_syntax_module
                                .declarations
                                .iter()
                                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                                .filter_map(|documented_declaration| {
                                    documented_declaration.declaration.as_ref()
                                })
                        {
                            if let GrenSyntaxDeclaration::ChoiceType {
                                name: Some(exposed_choice_type_name_node),
                                parameters: _,
                                equals_key_symbol_range: _,
                                variant0_name: maybe_exposed_choice_type_variant0_name,
                                variant0_value: _,
                                variant1_up: exposed_choice_type_variant1_up,
                            } = &declaration_node.value
                                && choice_type_expose_name.value
                                    == exposed_choice_type_name_node.value
                            {
                                if let Some(exposed_choice_type_variant0_name_node) =
                                    maybe_exposed_choice_type_variant0_name
                                {
                                    exposed_symbols
                                        .push(&exposed_choice_type_variant0_name_node.value);
                                }
                                for exposed_choice_type_variant in exposed_choice_type_variant1_up {
                                    if let Some(exposed_choice_type_variant_name_node) =
                                        &exposed_choice_type_variant.name
                                    {
                                        exposed_symbols
                                            .push(&exposed_choice_type_variant_name_node.value);
                                    }
                                }
                                break 'until_origin_choice_type_declaration_found;
                            }
                        }
                    }
                    GrenSyntaxExpose::Operator(maybe_symbol) => {
                        if let Some(symbol_node) = maybe_symbol {
                            exposed_symbols.push(symbol_node.value);
                        }
                    }
                    GrenSyntaxExpose::Type(name) => {
                        exposed_symbols.push(name);
                    }
                    GrenSyntaxExpose::Variable(name) => {
                        exposed_symbols.push(name);
                    }
                }
            }
            exposed_symbols
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineSpan {
    Single,
    Multiple,
}
fn linebreak_indented_into(so_far: &mut String, indent: usize) {
    so_far.push('\n');
    so_far.extend(std::iter::repeat_n(' ', indent));
}
fn space_or_linebreak_indented_into(so_far: &mut String, line_span: LineSpan, indent: usize) {
    match line_span {
        LineSpan::Single => {
            so_far.push(' ');
        }
        LineSpan::Multiple => {
            linebreak_indented_into(so_far, indent);
        }
    }
}

fn gren_syntax_type_to_string(
    module_origin_lookup: &ModuleOriginLookup,
    gren_syntax_type: GrenSyntaxNode<&GrenSyntaxType>,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
) -> String {
    let mut builder: String = String::new();
    gren_syntax_type_not_parenthesized_into(
        &mut builder,
        indent,
        |qualified| look_up_origin_module(module_origin_lookup, qualified),
        comments, // pass from parens and slice?
        gren_syntax_type,
    );
    builder
}

fn gren_syntax_comments_in_range(
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    range: lsp_types::Range,
) -> &[GrenSyntaxNode<GrenSyntaxComment>] {
    if comments.is_empty() {
        return &[];
    }
    let comments_in_range_start_index: usize = comments
        .binary_search_by(|comment_node| comment_node.range.start.cmp(&range.start))
        .unwrap_or_else(|i| i);
    let comments_in_range_end_exclusive_index: usize = comments
        .binary_search_by(|comment_node| comment_node.range.start.cmp(&range.end))
        .unwrap_or_else(|i| i);
    &comments[comments_in_range_start_index..comments_in_range_end_exclusive_index]
}
fn gren_syntax_comments_from_position(
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    start_position: lsp_types::Position,
) -> &[GrenSyntaxNode<GrenSyntaxComment>] {
    let comments_in_range_start_index: usize = comments
        .binary_search_by(|comment_node| comment_node.range.start.cmp(&start_position))
        .unwrap_or_else(|i| i);
    &comments[comments_in_range_start_index..]
}

/// same caveat as `gren_syntax_comments_into` apply.
/// use in combination with `gren_syntax_comments_in_range`
fn gren_syntax_comments_then_linebreak_indented_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
) {
    for comment_node_in_range in comments {
        gren_syntax_comment_into(so_far, &comment_node_in_range.value);
        linebreak_indented_into(so_far, indent);
    }
}

/// use in combination with `gren_syntax_comments_in_range`
fn gren_syntax_comments_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
) {
    let mut comments_iterator = comments.iter();
    let Some(first_comment_node) = comments_iterator.next() else {
        return;
    };
    gren_syntax_comment_into(so_far, &first_comment_node.value);
    for comment_node_in_range in comments_iterator {
        linebreak_indented_into(so_far, indent);
        gren_syntax_comment_into(so_far, &comment_node_in_range.value);
    }
}
fn gren_syntax_comment_into(so_far: &mut String, comment: &GrenSyntaxComment) {
    match comment.kind {
        GrenSyntaxCommentKind::UntilLinebreak => {
            so_far.push_str("--");
            so_far.push_str(&comment.content);
        }
        GrenSyntaxCommentKind::Block => {
            so_far.push_str("{-");
            so_far.push_str(&comment.content);
            so_far.push_str("-}");
        }
    }
}

fn gren_syntax_type_to_unparenthesized(
    gren_syntax_type: GrenSyntaxNode<&GrenSyntaxType>,
) -> Option<GrenSyntaxNode<&GrenSyntaxType>> {
    match gren_syntax_type.value {
        GrenSyntaxType::Parenthesized(maybe_in_parens) => match maybe_in_parens {
            None => None,
            Some(in_parens) => {
                gren_syntax_type_to_unparenthesized(gren_syntax_node_unbox(in_parens))
            }
        },
        _ => Some(gren_syntax_type),
    }
}

fn next_indent(current_indent: usize) -> usize {
    (current_indent + 1).next_multiple_of(4)
}

fn gren_syntax_type_not_parenthesized_into<'a>(
    so_far: &mut String,
    indent: usize,
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    type_node: GrenSyntaxNode<&'a GrenSyntaxType>,
) {
    match type_node.value {
        GrenSyntaxType::Construct {
            reference,
            arguments,
        } => {
            let line_span: LineSpan = gren_syntax_range_line_span(type_node.range, comments);
            let assigned_qualification: &str = assign_qualification(GrenQualified {
                qualification: &reference.value.qualification,
                name: &reference.value.name,
            });
            if !assigned_qualification.is_empty() {
                so_far.push_str(assigned_qualification);
                so_far.push('.');
            }
            so_far.push_str(&reference.value.name);
            let mut previous_syntax_end: lsp_types::Position = reference.range.end;
            for argument_node in arguments {
                space_or_linebreak_indented_into(so_far, line_span, next_indent(indent));
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: previous_syntax_end,
                            end: argument_node.range.start,
                        },
                    ),
                );
                gren_syntax_type_parenthesized_if_space_separated_into(
                    so_far,
                    next_indent(indent),
                    assign_qualification,
                    comments,
                    argument_node.range,
                    gren_syntax_type_to_unparenthesized(gren_syntax_node_as_ref(argument_node)),
                );
                previous_syntax_end = argument_node.range.end;
            }
        }
        GrenSyntaxType::Function {
            input,
            arrow_key_symbol_range: _,
            output: maybe_output,
        } => {
            let input_unparenthesized: Option<GrenSyntaxNode<&GrenSyntaxType>> =
                gren_syntax_type_to_unparenthesized(gren_syntax_node_unbox(input));
            match input_unparenthesized {
                Some(GrenSyntaxNode {
                    value: GrenSyntaxType::Function { .. },
                    range: _,
                }) => {
                    gren_syntax_type_parenthesized_into(
                        so_far,
                        indent,
                        assign_qualification,
                        comments,
                        input.range,
                        input_unparenthesized,
                    );
                }
                _ => {
                    gren_syntax_type_not_parenthesized_into(
                        so_far,
                        indent,
                        assign_qualification,
                        comments,
                        gren_syntax_node_unbox(input),
                    );
                }
            }
            space_or_linebreak_indented_into(
                so_far,
                gren_syntax_range_line_span(type_node.range, comments),
                indent,
            );
            let comments_around_arrow: &[GrenSyntaxNode<GrenSyntaxComment>] =
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: input.range.end,
                        end: maybe_output
                            .as_ref()
                            .map(|node| node.range.start)
                            .unwrap_or(type_node.range.end),
                    },
                );
            if let Some(output_node) = maybe_output {
                so_far.push_str("->");
                space_or_linebreak_indented_into(
                    so_far,
                    if comments_around_arrow.is_empty() {
                        gren_syntax_range_line_span(output_node.range, comments)
                    } else {
                        LineSpan::Multiple
                    },
                    next_indent(indent),
                );
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    next_indent(indent),
                    comments_around_arrow,
                );
                gren_syntax_type_not_parenthesized_into(
                    so_far,
                    next_indent(indent),
                    assign_qualification,
                    comments,
                    gren_syntax_node_unbox(output_node),
                );
            } else {
                if !comments_around_arrow.is_empty() {
                    linebreak_indented_into(so_far, indent);
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        indent,
                        comments_around_arrow,
                    );
                }
                so_far.push_str("-> ");
            }
        }
        GrenSyntaxType::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens
                && let Some(innermost) =
                    gren_syntax_type_to_unparenthesized(gren_syntax_node_unbox(in_parens))
            {
                let comments_before_innermost: &[GrenSyntaxNode<GrenSyntaxComment>] =
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: type_node.range.start,
                            end: innermost.range.start,
                        },
                    );
                let comments_after_innermost: &[GrenSyntaxNode<GrenSyntaxComment>] =
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: innermost.range.end,
                            end: type_node.range.end,
                        },
                    );
                if comments_before_innermost.is_empty() && comments_after_innermost.is_empty() {
                    gren_syntax_type_not_parenthesized_into(
                        so_far,
                        indent,
                        assign_qualification,
                        comments,
                        innermost,
                    );
                } else {
                    gren_syntax_type_parenthesized_into(
                        so_far,
                        indent,
                        assign_qualification,
                        comments,
                        type_node.range,
                        Some(innermost),
                    );
                }
            } else {
                gren_syntax_type_parenthesized_into(
                    so_far,
                    indent,
                    assign_qualification,
                    comments,
                    type_node.range,
                    None,
                );
            }
        }
        GrenSyntaxType::Record(fields) => match fields.split_first() {
            None => {
                let comments_in_curlies: &[GrenSyntaxNode<GrenSyntaxComment>] =
                    gren_syntax_comments_in_range(comments, type_node.range);
                if comments_in_curlies.is_empty() {
                    so_far.push_str("{}");
                } else {
                    so_far.push('{');
                    gren_syntax_comments_into(so_far, indent + 1, comments);
                    linebreak_indented_into(so_far, indent);
                    so_far.push('}');
                }
            }
            Some((field0, field1_up)) => {
                let line_span: LineSpan = gren_syntax_range_line_span(type_node.range, comments);
                so_far.push_str("{ ");
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent + 2,
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: type_node.range.start,
                            end: field0.name.range.start,
                        },
                    ),
                );
                let previous_syntax_end: lsp_types::Position = gren_syntax_type_fields_into_string(
                    so_far,
                    indent,
                    assign_qualification,
                    comments,
                    line_span,
                    field0,
                    field1_up,
                );
                space_or_linebreak_indented_into(so_far, line_span, indent);
                let comments_before_closing_curly = gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: previous_syntax_end,
                        end: type_node.range.end,
                    },
                );
                if !comments_before_closing_curly.is_empty() {
                    linebreak_indented_into(so_far, indent);
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        indent,
                        comments_before_closing_curly,
                    );
                }
                so_far.push('}');
            }
        },
        GrenSyntaxType::RecordExtension {
            record_variable: maybe_record_variable,
            bar_key_symbol_range: _,
            fields,
        } => {
            let line_span: LineSpan = gren_syntax_range_line_span(type_node.range, comments);
            so_far.push_str("{ ");
            let mut previous_syntax_end: lsp_types::Position = type_node.range.start;
            if let Some(record_variable_node) = maybe_record_variable {
                so_far.push_str(&record_variable_node.value);
                previous_syntax_end = record_variable_node.range.end;
            }
            if let Some((field0, field1_up)) = fields.split_first() {
                space_or_linebreak_indented_into(so_far, line_span, indent);
                so_far.push_str("| ");
                previous_syntax_end = gren_syntax_type_fields_into_string(
                    so_far,
                    indent,
                    assign_qualification,
                    comments,
                    line_span,
                    field0,
                    field1_up,
                );
            }
            space_or_linebreak_indented_into(so_far, line_span, indent);
            let comments_before_closing_curly = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: type_node.range.end,
                },
            );
            if !comments_before_closing_curly.is_empty() {
                linebreak_indented_into(so_far, indent);
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent + 2,
                    comments_before_closing_curly,
                );
            }
            so_far.push('}');
        }
        GrenSyntaxType::Variable(name) => {
            so_far.push_str(name);
        }
    }
}
fn gren_syntax_type_parenthesized_into<'a>(
    so_far: &mut String,
    indent: usize,
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    full_range: lsp_types::Range,
    maybe_innermost: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
) {
    so_far.push('(');
    let start_so_far_length: usize = so_far.len();
    match maybe_innermost {
        None => {
            gren_syntax_comments_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(comments, full_range),
            );
        }
        Some(innermost) => {
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: full_range.start,
                        end: innermost.range.start,
                    },
                ),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: innermost.range.end,
                        end: full_range.end,
                    },
                ),
            );
            gren_syntax_type_not_parenthesized_into(
                so_far,
                indent + 1,
                assign_qualification,
                comments,
                innermost,
            );
        }
    }
    if so_far[start_so_far_length..].contains('\n') {
        linebreak_indented_into(so_far, indent);
    }
    so_far.push(')');
}
fn gren_syntax_type_parenthesized_if_space_separated_into<'a>(
    so_far: &mut String,
    indent: usize,
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    full_range: lsp_types::Range,
    maybe_unparenthesized: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
) {
    match maybe_unparenthesized {
        None => {
            gren_syntax_type_parenthesized_into(
                so_far,
                indent,
                assign_qualification,
                comments,
                full_range,
                None,
            );
        }
        Some(unparenthesized) => {
            let is_space_separated: bool = match unparenthesized.value {
                GrenSyntaxType::Variable(_)
                | GrenSyntaxType::Parenthesized(_)
                | GrenSyntaxType::Record(_)
                | GrenSyntaxType::RecordExtension { .. } => false,
                GrenSyntaxType::Function { .. } => true,
                GrenSyntaxType::Construct {
                    reference: _,
                    arguments,
                } => !arguments.is_empty(),
            };
            if is_space_separated {
                gren_syntax_type_parenthesized_into(
                    so_far,
                    indent,
                    assign_qualification,
                    comments,
                    full_range,
                    Some(unparenthesized),
                );
            } else {
                gren_syntax_type_not_parenthesized_into(
                    so_far,
                    indent,
                    assign_qualification,
                    comments,
                    unparenthesized,
                );
            }
        }
    }
}
/// returns the last syntax end position
fn gren_syntax_type_fields_into_string<'a>(
    so_far: &mut String,
    indent: usize,
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    line_span: LineSpan,
    field0: &'a GrenSyntaxTypeField,
    field1_up: &'a [GrenSyntaxTypeField],
) -> lsp_types::Position {
    so_far.push_str(&field0.name.value);
    let mut previous_syntax_end: lsp_types::Position = field0.name.range.end;
    so_far.push_str(" :");
    if let Some(field0_value_node) = &field0.value {
        let comments_before_field0_value = gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: field0.name.range.end,
                end: field0_value_node.range.start,
            },
        );
        space_or_linebreak_indented_into(
            so_far,
            if comments_before_field0_value.is_empty() {
                gren_syntax_range_line_span(
                    lsp_types::Range {
                        start: field0.name.range.end,
                        end: field0_value_node.range.end,
                    },
                    comments,
                )
            } else {
                LineSpan::Multiple
            },
            next_indent(indent + 2),
        );
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent + 2),
            comments_before_field0_value,
        );
        gren_syntax_type_not_parenthesized_into(
            so_far,
            next_indent(indent + 2),
            assign_qualification,
            comments,
            gren_syntax_node_as_ref(field0_value_node),
        );
        previous_syntax_end = field0_value_node.range.end;
    }
    for field in field1_up {
        if line_span == LineSpan::Multiple {
            linebreak_indented_into(so_far, indent);
        }
        so_far.push_str(", ");
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            indent + 2,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: field.name.range.start,
                },
            ),
        );
        so_far.push_str(&field.name.value);
        previous_syntax_end = field.name.range.end;
        so_far.push_str(" :");
        if let Some(field_value_node) = &field.value {
            let comments_before_field_value = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: field.name.range.end,
                    end: field_value_node.range.start,
                },
            );
            space_or_linebreak_indented_into(
                so_far,
                if comments_before_field_value.is_empty() {
                    gren_syntax_range_line_span(
                        lsp_types::Range {
                            start: field.name.range.end,
                            end: field_value_node.range.end,
                        },
                        comments,
                    )
                } else {
                    LineSpan::Multiple
                },
                next_indent(indent + 2),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                next_indent(indent + 2),
                comments_before_field_value,
            );
            gren_syntax_type_not_parenthesized_into(
                so_far,
                next_indent(indent + 2),
                assign_qualification,
                comments,
                gren_syntax_node_as_ref(field_value_node),
            );
            previous_syntax_end = field_value_node.range.end;
        }
    }
    previous_syntax_end
}
fn gren_syntax_pattern_not_parenthesized_into(
    so_far: &mut String,
    pattern_node: GrenSyntaxNode<&GrenSyntaxPattern>,
) {
    match pattern_node.value {
        GrenSyntaxPattern::Ignored(maybe_name) => {
            so_far.push('_');
            if let Some(name) = maybe_name {
                so_far.push_str(name);
            }
        }
        GrenSyntaxPattern::Char(maybe_char) => gren_char_into(so_far, *maybe_char),
        GrenSyntaxPattern::Int {
            base,
            value: value_or_err,
        } => {
            gren_int_into(so_far, *base, value_or_err);
        }
        GrenSyntaxPattern::String {
            content,
            quoting_style,
        } => gren_string_into(so_far, *quoting_style, content),
        GrenSyntaxPattern::Variable(name) => {
            so_far.push_str(name);
        }
        GrenSyntaxPattern::As {
            pattern,
            as_keyword_range: _,
            variable: maybe_variable,
        } => {
            gren_syntax_pattern_not_parenthesized_into(so_far, gren_syntax_node_unbox(pattern));
            so_far.push_str(" as ");
            if let Some(variable_node) = maybe_variable {
                so_far.push_str(&variable_node.value);
            }
        }
        GrenSyntaxPattern::Parenthesized(maybe_in_parens) => match maybe_in_parens {
            None => {
                so_far.push_str("()");
            }
            Some(in_parens) => {
                gren_syntax_pattern_not_parenthesized_into(
                    so_far,
                    gren_syntax_node_unbox(in_parens),
                );
            }
        },
        GrenSyntaxPattern::Record(field_names) => {
            let mut field_names_iterator = field_names.iter();
            match field_names_iterator.next() {
                None => {
                    so_far.push_str("{}");
                }
                Some(field0) => {
                    so_far.push_str("{ ");
                    gren_syntax_pattern_field_into(so_far, field0);
                    for field in field_names_iterator {
                        so_far.push_str(", ");
                        gren_syntax_pattern_field_into(so_far, field);
                    }
                    so_far.push_str(" }");
                }
            }
        }
        GrenSyntaxPattern::Variant {
            reference,
            value: maybe_value,
        } => {
            gren_qualified_name_into(so_far, &reference.value);
            if let Some(value_node) = maybe_value {
                so_far.push(' ');
                gren_syntax_pattern_parenthesized_if_space_separated_into(
                    so_far,
                    gren_syntax_node_unbox(value_node),
                );
            }
        }
    }
}
fn gren_syntax_pattern_field_into(so_far: &mut String, field: &GrenSyntaxPatternField) {
    so_far.push_str(&field.name.value);
    match &field.value {
        None => {
            if field.equals_key_symbol_range.is_some() {
                so_far.push_str(" = ");
            }
        }
        Some(field_value) => {
            so_far.push_str(" = ");
            gren_syntax_pattern_not_parenthesized_into(
                so_far,
                gren_syntax_node_as_ref(field_value),
            );
        }
    }
}
fn gren_qualified_name_into(so_far: &mut String, qualified: &GrenQualifiedName) {
    if !qualified.qualification.is_empty() {
        so_far.push_str(&qualified.qualification);
        so_far.push('.');
    }
    so_far.push_str(&qualified.name);
}
fn gren_syntax_pattern_parenthesized_into(
    so_far: &mut String,
    pattern_node: GrenSyntaxNode<&GrenSyntaxPattern>,
) {
    so_far.push('(');
    gren_syntax_pattern_not_parenthesized_into(so_far, pattern_node);
    so_far.push(')');
}
fn gren_syntax_pattern_parenthesized_if_space_separated_into(
    so_far: &mut String,
    pattern_node: GrenSyntaxNode<&GrenSyntaxPattern>,
) {
    match pattern_node.value {
        GrenSyntaxPattern::As { .. } => {
            gren_syntax_pattern_parenthesized_into(so_far, pattern_node);
        }
        _ => {
            gren_syntax_pattern_not_parenthesized_into(so_far, pattern_node);
        }
    }
}
fn gren_char_into(so_far: &mut String, maybe_char: Option<char>) {
    match maybe_char {
        None => {
            so_far.push_str("''");
        }
        Some(char) => {
            so_far.push('\'');
            match char {
                '\'' => so_far.push_str("\\'"),
                '\\' => so_far.push_str("\\\\"),
                '\t' => so_far.push_str("\\t"),
                '\n' => so_far.push_str("\\n"),
                '\u{000D}' => so_far.push_str("\\u{000D}"),
                other_character => {
                    if gren_char_needs_unicode_escaping(other_character) {
                        gren_unicode_char_escape_into(so_far, other_character);
                    } else {
                        so_far.push(other_character);
                    }
                }
            }
            so_far.push('\'');
        }
    }
}
fn gren_char_needs_unicode_escaping(char: char) -> bool {
    (char.len_utf16() >= 2) || char.is_control()
}
fn gren_unicode_char_escape_into(so_far: &mut String, char: char) {
    for utf16_code in char.encode_utf16(&mut [0; 2]) {
        use std::fmt::Write as _;
        let _ = write!(so_far, "\\u{{{:04X}}}", utf16_code);
    }
}
fn gren_int_into(
    so_far: &mut String,
    base: GrenSyntaxIntBase,
    value_or_err: &Result<i64, Box<str>>,
) {
    match value_or_err {
        Err(value_as_string) => match base {
            GrenSyntaxIntBase::IntBase10 => {
                so_far.push_str(value_as_string);
            }
            GrenSyntaxIntBase::IntBase16 => {
                so_far.push_str("0x");
                so_far.push_str(value_as_string);
            }
        },
        &Ok(value) => match base {
            GrenSyntaxIntBase::IntBase10 => {
                use std::fmt::Write as _;
                let _ = write!(so_far, "{}", value);
            }
            GrenSyntaxIntBase::IntBase16 => {
                use std::fmt::Write as _;
                let _ = write!(so_far, "0x{:02x}", value);
                if value <= 0xFF {
                    use std::fmt::Write as _;
                    let _ = write!(so_far, "\\u{{{:02X}}}", value);
                } else if value <= 0xFFFF {
                    use std::fmt::Write as _;
                    let _ = write!(so_far, "\\u{{{:04X}}}", value);
                } else if value <= 0xFFFF_FFFF {
                    use std::fmt::Write as _;
                    let _ = write!(so_far, "\\u{{{:08X}}}", value);
                } else {
                    use std::fmt::Write as _;
                    let _ = write!(so_far, "\\u{{{:016X}}}", value);
                }
            }
        },
    }
}
fn gren_string_into(
    so_far: &mut String,
    quoting_style: GrenSyntaxStringQuotingStyle,
    content: &str,
) {
    match quoting_style {
        GrenSyntaxStringQuotingStyle::SingleQuoted => {
            so_far.push('"');
            for char in content.chars() {
                match char {
                    '\"' => so_far.push_str("\\\""),
                    '\\' => so_far.push_str("\\\\"),
                    '\t' => so_far.push_str("\\t"),
                    '\n' => so_far.push_str("\\n"),
                    '\u{000D}' => so_far.push_str("\\u{000D}"),
                    other_character => {
                        if gren_char_needs_unicode_escaping(other_character) {
                            gren_unicode_char_escape_into(so_far, other_character);
                        } else {
                            so_far.push(other_character);
                        }
                    }
                }
            }
            so_far.push('"');
        }
        GrenSyntaxStringQuotingStyle::TripleQuoted => {
            so_far.push_str("\"\"\"");
            // because only quotes connected to the ending """ should be escaped to \"
            let mut quote_count_to_insert: usize = 0;
            'pushing_escaped_content: for char in content.chars() {
                if char == '\"' {
                    quote_count_to_insert += 1;
                    continue 'pushing_escaped_content;
                }
                so_far.extend(std::iter::repeat_n('\"', quote_count_to_insert));
                match char {
                    '\\' => so_far.push_str("\\\\"),
                    '\t' => so_far.push_str("\\t"),
                    '\r' => so_far.push('\r'),
                    '\n' => so_far.push('\n'),
                    '\"' => {
                        quote_count_to_insert += 1;
                    }
                    other_character => {
                        if gren_char_needs_unicode_escaping(other_character) {
                            gren_unicode_char_escape_into(so_far, other_character);
                        } else {
                            so_far.push(other_character);
                        }
                    }
                }
            }
            so_far.extend(std::iter::repeat_n("\\\"", quote_count_to_insert));
            so_far.push_str("\"\"\"");
        }
    }
}
fn gren_syntax_expression_not_parenthesized_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) {
    match expression_node.value {
        GrenSyntaxExpression::Call {
            called: called_node,
            argument0: argument0_node,
            argument1_up,
        } => {
            let comments_before_argument0: &[GrenSyntaxNode<GrenSyntaxComment>] =
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: called_node.range.end,
                        end: argument0_node.range.start,
                    },
                );
            let line_span_before_argument0: LineSpan = if comments_before_argument0.is_empty()
                && gren_syntax_expression_line_span(comments, gren_syntax_node_unbox(called_node))
                    == LineSpan::Single
                && gren_syntax_expression_line_span(
                    comments,
                    gren_syntax_node_unbox(argument0_node),
                ) == LineSpan::Single
            {
                LineSpan::Single
            } else {
                LineSpan::Multiple
            };
            let full_line_span: LineSpan = match line_span_before_argument0 {
                LineSpan::Multiple => LineSpan::Multiple,
                LineSpan::Single => gren_syntax_expression_line_span(comments, expression_node),
            };
            gren_syntax_expression_parenthesized_if_space_separated_into(
                so_far,
                indent,
                comments,
                gren_syntax_node_unbox(called_node),
            );
            space_or_linebreak_indented_into(
                so_far,
                line_span_before_argument0,
                next_indent(indent),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                next_indent(indent),
                comments_before_argument0,
            );
            gren_syntax_expression_parenthesized_if_space_separated_into(
                so_far,
                next_indent(indent),
                comments,
                gren_syntax_node_unbox(argument0_node),
            );
            let mut previous_syntax_end: lsp_types::Position = argument0_node.range.end;
            for argument_node in argument1_up.iter().map(gren_syntax_node_as_ref) {
                space_or_linebreak_indented_into(so_far, full_line_span, next_indent(indent));
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: previous_syntax_end,
                            end: argument_node.range.start,
                        },
                    ),
                );
                gren_syntax_expression_parenthesized_if_space_separated_into(
                    so_far,
                    next_indent(indent),
                    comments,
                    argument_node,
                );
                previous_syntax_end = argument_node.range.end;
            }
        }
        GrenSyntaxExpression::CaseOf {
            matched: maybe_matched,
            of_keyword_range: maybe_of_keyword_range,
            cases,
        } => {
            so_far.push_str("when");
            let previous_syntax_that_covered_comments_end: lsp_types::Position;
            match maybe_matched {
                None => match maybe_of_keyword_range {
                    None => {
                        so_far.push_str("  ");
                        previous_syntax_that_covered_comments_end = expression_node.range.start;
                    }
                    Some(of_keyword_range) => {
                        let comments_between_case_and_of_keywords: &[GrenSyntaxNode<
                            GrenSyntaxComment,
                        >] = gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: expression_node.range.start,
                                end: of_keyword_range.end,
                            },
                        );
                        if comments_between_case_and_of_keywords.is_empty() {
                            so_far.push_str("  ");
                        } else {
                            linebreak_indented_into(so_far, next_indent(indent));
                            gren_syntax_comments_into(
                                so_far,
                                next_indent(indent),
                                comments_between_case_and_of_keywords,
                            );
                            linebreak_indented_into(so_far, indent);
                        }
                        previous_syntax_that_covered_comments_end = of_keyword_range.end;
                    }
                },
                Some(matched_node) => {
                    let comments_before_matched: &[GrenSyntaxNode<GrenSyntaxComment>] =
                        gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: expression_node.range.start,
                                end: matched_node.range.start,
                            },
                        );
                    let comments_before_of_keyword: &[GrenSyntaxNode<GrenSyntaxComment>] = if cases
                        .is_empty()
                        && let Some(of_keyword_range) = maybe_of_keyword_range
                    {
                        gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: matched_node.range.start,
                                end: of_keyword_range.start,
                            },
                        )
                    } else {
                        &[]
                    };
                    let before_cases_line_span: LineSpan = if comments_before_matched.is_empty()
                        && comments_before_of_keyword.is_empty()
                    {
                        gren_syntax_expression_line_span(
                            comments,
                            gren_syntax_node_unbox(matched_node),
                        )
                    } else {
                        LineSpan::Multiple
                    };
                    space_or_linebreak_indented_into(
                        so_far,
                        before_cases_line_span,
                        next_indent(indent),
                    );
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        next_indent(indent),
                        comments_before_matched,
                    );
                    gren_syntax_expression_not_parenthesized_into(
                        so_far,
                        next_indent(indent),
                        comments,
                        gren_syntax_node_unbox(matched_node),
                    );
                    space_or_linebreak_indented_into(so_far, before_cases_line_span, indent);
                    if let Some(of_keyword_range) = maybe_of_keyword_range
                        && !comments_before_of_keyword.is_empty()
                    {
                        linebreak_indented_into(so_far, indent);
                        gren_syntax_comments_then_linebreak_indented_into(
                            so_far,
                            next_indent(indent),
                            comments_before_matched,
                        );
                        previous_syntax_that_covered_comments_end = of_keyword_range.end;
                    } else {
                        previous_syntax_that_covered_comments_end = matched_node.range.end;
                    }
                }
            }
            so_far.push_str("is");
            linebreak_indented_into(so_far, next_indent(indent));
            if let Some((case0, case1_up)) = cases.split_first() {
                let mut previous_syntax_end: lsp_types::Position = gren_syntax_case_into(
                    so_far,
                    next_indent(indent),
                    comments,
                    previous_syntax_that_covered_comments_end,
                    case0,
                );
                for case in case1_up {
                    so_far.push('\n');
                    linebreak_indented_into(so_far, next_indent(indent));
                    previous_syntax_end = gren_syntax_case_into(
                        so_far,
                        next_indent(indent),
                        comments,
                        previous_syntax_end,
                        case,
                    );
                }
            }
        }
        GrenSyntaxExpression::Char(maybe_char) => {
            gren_char_into(so_far, *maybe_char);
        }
        GrenSyntaxExpression::Float(value_or_whatever) => match value_or_whatever {
            Err(whatever) => {
                so_far.push_str(whatever);
            }
            Ok(value) => {
                use std::fmt::Write as _;
                let _ = write!(so_far, "{}", *value);
            }
        },
        GrenSyntaxExpression::IfThenElse {
            condition: maybe_condition,
            then_keyword_range: maybe_then_keyword_range,
            on_true: maybe_on_true,
            else_keyword_range: maybe_else_keyword_range,
            on_false: maybe_on_false,
        } => {
            so_far.push_str("if");
            let until_condition: lsp_types::Position = maybe_condition
                .as_ref()
                .map(|node| node.range.start)
                .unwrap_or(expression_node.range.start);
            let before_then_keyword: lsp_types::Position = maybe_then_keyword_range
                .map(|range| range.start)
                .or_else(|| maybe_condition.as_ref().map(|node| node.range.end))
                .unwrap_or(expression_node.range.start);
            let after_on_true: lsp_types::Position = maybe_on_true
                .as_ref()
                .map(|node| node.range.end)
                .unwrap_or(before_then_keyword);
            let comments_before_condition = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: expression_node.range.start,
                    end: until_condition,
                },
            );
            let comments_before_then_keyword: &[GrenSyntaxNode<GrenSyntaxComment>] =
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: expression_node.range.start,
                        end: before_then_keyword,
                    },
                );
            let before_condition_line_span: LineSpan = if comments_before_condition.is_empty()
                && comments_before_then_keyword.is_empty()
            {
                match maybe_condition {
                    None => LineSpan::Single,
                    Some(condition_node) => gren_syntax_expression_line_span(
                        comments,
                        gren_syntax_node_unbox(condition_node),
                    ),
                }
            } else {
                LineSpan::Multiple
            };
            space_or_linebreak_indented_into(
                so_far,
                before_condition_line_span,
                next_indent(indent),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                next_indent(indent),
                comments_before_condition,
            );
            if let Some(condition_node) = maybe_condition {
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    next_indent(indent),
                    comments,
                    gren_syntax_node_unbox(condition_node),
                );
            }
            space_or_linebreak_indented_into(so_far, before_condition_line_span, indent);
            if !comments_before_then_keyword.is_empty() {
                linebreak_indented_into(so_far, indent);
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent,
                    comments_before_then_keyword,
                );
            }
            so_far.push_str("then");
            linebreak_indented_into(so_far, next_indent(indent));
            if let Some(on_true_node) = maybe_on_true {
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: before_then_keyword,
                            end: on_true_node.range.start,
                        },
                    ),
                );
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    next_indent(indent),
                    comments,
                    gren_syntax_node_unbox(on_true_node),
                );
                so_far.push('\n');
            }
            linebreak_indented_into(so_far, indent);
            if maybe_on_false.is_none()
                && let Some(else_keyword_range) = maybe_else_keyword_range
            {
                linebreak_indented_into(so_far, indent);
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent,
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: after_on_true,
                            end: else_keyword_range.start,
                        },
                    ),
                );
            }
            so_far.push_str("else");
            match maybe_on_false {
                None => {
                    linebreak_indented_into(so_far, next_indent(indent));
                }
                Some(on_false_node) => {
                    match gren_syntax_expression_to_unparenthesized(gren_syntax_node_unbox(
                        on_false_node,
                    )) {
                        None => {
                            linebreak_indented_into(so_far, next_indent(indent));
                            gren_syntax_comments_then_linebreak_indented_into(
                                so_far,
                                next_indent(indent),
                                gren_syntax_comments_in_range(
                                    comments,
                                    lsp_types::Range {
                                        start: after_on_true,
                                        end: on_false_node.range.start,
                                    },
                                ),
                            );
                            gren_syntax_expression_not_parenthesized_into(
                                so_far,
                                next_indent(indent),
                                comments,
                                gren_syntax_node_unbox(on_false_node),
                            );
                        }
                        Some(on_false_maybe_innermost) => {
                            let comments_after_on_false_innermost: &[GrenSyntaxNode<
                                GrenSyntaxComment,
                            >] = gren_syntax_comments_in_range(
                                comments,
                                lsp_types::Range {
                                    start: on_false_maybe_innermost.range.end,
                                    end: on_false_node.range.end,
                                },
                            );
                            if comments_after_on_false_innermost.is_empty()
                                && let GrenSyntaxExpression::IfThenElse { .. } =
                                    on_false_maybe_innermost.value
                            {
                                let comments_before_on_false_innermost: &[GrenSyntaxNode<
                                    GrenSyntaxComment,
                                >] = gren_syntax_comments_in_range(
                                    comments,
                                    lsp_types::Range {
                                        start: on_false_node.range.start,
                                        end: on_false_maybe_innermost.range.start,
                                    },
                                );
                                space_or_linebreak_indented_into(
                                    so_far,
                                    if comments_before_on_false_innermost.is_empty() {
                                        LineSpan::Single
                                    } else {
                                        LineSpan::Multiple
                                    },
                                    indent,
                                );
                                gren_syntax_comments_then_linebreak_indented_into(
                                    so_far,
                                    indent,
                                    comments_before_on_false_innermost,
                                );
                                gren_syntax_expression_not_parenthesized_into(
                                    so_far,
                                    indent,
                                    comments,
                                    on_false_maybe_innermost,
                                );
                            } else {
                                linebreak_indented_into(so_far, next_indent(indent));
                                gren_syntax_comments_then_linebreak_indented_into(
                                    so_far,
                                    next_indent(indent),
                                    gren_syntax_comments_in_range(
                                        comments,
                                        lsp_types::Range {
                                            start: after_on_true,
                                            end: on_false_node.range.start,
                                        },
                                    ),
                                );
                                gren_syntax_expression_not_parenthesized_into(
                                    so_far,
                                    next_indent(indent),
                                    comments,
                                    gren_syntax_node_unbox(on_false_node),
                                );
                            }
                        }
                    }
                }
            }
        }
        GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
            left: left_node,
            operator: operator_node,
            right: maybe_right,
        } => {
            let line_span: LineSpan = gren_syntax_expression_line_span(comments, expression_node);
            gren_syntax_expression_parenthesized_if_not_call_but_space_separated_into(
                so_far,
                indent,
                comments,
                gren_syntax_node_unbox(left_node),
            );
            match maybe_right {
                None => {
                    space_or_linebreak_indented_into(so_far, line_span, next_indent(indent));
                    let comments_before_operator = gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: left_node.range.end,
                            end: operator_node.range.start,
                        },
                    );
                    if !comments_before_operator.is_empty() {
                        linebreak_indented_into(so_far, next_indent(indent));
                        gren_syntax_comments_then_linebreak_indented_into(
                            so_far,
                            next_indent(indent),
                            comments_before_operator,
                        );
                    }
                    so_far.push_str(operator_node.value);
                }
                Some(right_node) => {
                    space_or_linebreak_indented_into(so_far, line_span, next_indent(indent));
                    so_far.push_str(operator_node.value);
                    so_far.push(' ');
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        next_indent(indent) + operator_node.value.len() + 1,
                        gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: left_node.range.end,
                                end: right_node.range.start,
                            },
                        ),
                    );
                    let mut previous_operator: &str = operator_node.value;
                    let mut next_right_node: &GrenSyntaxNode<Box<GrenSyntaxExpression>> =
                        right_node;
                    'format_infix_operation_chain: loop {
                        match next_right_node.value.as_ref() {
                            GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
                                left: next_right_left_node,
                                operator: next_right_operator_node,
                                right: maybe_next_right_right,
                            } => {
                                gren_syntax_expression_parenthesized_if_not_call_but_space_separated_into(
                                    so_far,
                                    next_indent(indent) + next_right_operator_node.value.len() + 1,
                                    comments,
                                    gren_syntax_node_unbox(next_right_left_node),
                                );
                                space_or_linebreak_indented_into(
                                    so_far,
                                    line_span,
                                    next_indent(indent),
                                );
                                match maybe_next_right_right {
                                    None => {
                                        linebreak_indented_into(so_far, next_indent(indent));
                                        gren_syntax_comments_then_linebreak_indented_into(
                                            so_far,
                                            next_indent(indent),
                                            gren_syntax_comments_in_range(
                                                comments,
                                                lsp_types::Range {
                                                    start: next_right_left_node.range.end,
                                                    end: next_right_operator_node.range.start,
                                                },
                                            ),
                                        );
                                        so_far.push_str(next_right_operator_node.value);
                                        break 'format_infix_operation_chain;
                                    }
                                    Some(right_right_node) => {
                                        so_far.push_str(next_right_operator_node.value);
                                        so_far.push(' ');
                                        gren_syntax_comments_then_linebreak_indented_into(
                                            so_far,
                                            next_indent(indent)
                                                + next_right_operator_node.value.len()
                                                + 1,
                                            gren_syntax_comments_in_range(
                                                comments,
                                                lsp_types::Range {
                                                    start: next_right_left_node.range.end,
                                                    end: right_right_node.range.start,
                                                },
                                            ),
                                        );
                                        previous_operator = next_right_operator_node.value;
                                        next_right_node = right_right_node;
                                    }
                                }
                            }
                            _ => {
                                gren_syntax_expression_parenthesized_if_not_call_but_space_separated_into(
                                    so_far,
                                    next_indent(indent) + previous_operator.len() + 1,
                                    comments,
                                    gren_syntax_node_unbox(next_right_node),
                                );
                                break 'format_infix_operation_chain;
                            }
                        }
                    }
                }
            }
        }
        GrenSyntaxExpression::Integer {
            base,
            value: value_or_err,
        } => {
            gren_int_into(so_far, *base, value_or_err);
        }
        GrenSyntaxExpression::Lambda {
            parameters,
            arrow_key_symbol_range: maybe_arrow_key_symbol_range,
            result: maybe_result,
        } => {
            so_far.push('\\');
            let parameter_comments = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: expression_node.range.start,
                    end: if maybe_result.is_none()
                        && let Some(arrow_key_symbol_range) = maybe_arrow_key_symbol_range
                    {
                        arrow_key_symbol_range.end
                    } else {
                        parameters
                            .last()
                            .map(|node| node.range.end)
                            .unwrap_or(expression_node.range.start)
                    },
                },
            );
            let mut previous_parameter_end: lsp_types::Position = expression_node.range.start;
            if let Some((parameter0_node, parameter1_up)) = parameters.split_first() {
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent + 1,
                    gren_syntax_comments_in_range(
                        parameter_comments,
                        lsp_types::Range {
                            start: previous_parameter_end,
                            end: parameter0_node.range.start,
                        },
                    ),
                );
                gren_syntax_pattern_not_parenthesized_into(
                    so_far,
                    gren_syntax_node_as_ref(parameter0_node),
                );
                let line_span: LineSpan = if parameter_comments.is_empty() {
                    LineSpan::Single
                } else {
                    LineSpan::Multiple
                };
                for parameter_node in parameter1_up {
                    space_or_linebreak_indented_into(so_far, line_span, indent + 1);
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        indent + 1,
                        gren_syntax_comments_in_range(
                            parameter_comments,
                            lsp_types::Range {
                                start: previous_parameter_end,
                                end: parameter_node.range.start,
                            },
                        ),
                    );
                    gren_syntax_pattern_not_parenthesized_into(
                        so_far,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                    previous_parameter_end = parameter_node.range.end;
                }
                space_or_linebreak_indented_into(so_far, line_span, indent);
                previous_parameter_end = parameter0_node.range.end;
            }
            if maybe_result.is_none()
                && let Some(arrow_key_symbol_range) = maybe_arrow_key_symbol_range
                && let comments_before_arrow_key_symbol = gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: previous_parameter_end,
                        end: arrow_key_symbol_range.start,
                    },
                )
                && !comments_before_arrow_key_symbol.is_empty()
            {
                linebreak_indented_into(so_far, indent);
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent,
                    comments_before_arrow_key_symbol,
                );
            }
            so_far.push_str("->");
            space_or_linebreak_indented_into(
                so_far,
                gren_syntax_expression_line_span(comments, expression_node),
                next_indent(indent),
            );
            if let Some(result_node) = maybe_result {
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: previous_parameter_end,
                            end: result_node.range.start,
                        },
                    ),
                );
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    next_indent(indent),
                    comments,
                    gren_syntax_node_unbox(result_node),
                );
            }
        }
        GrenSyntaxExpression::LetIn {
            declarations,
            in_keyword_range: maybe_in_keyword_range,
            result: maybe_result,
        } => {
            so_far.push_str("let");
            let mut previous_declaration_end: lsp_types::Position = expression_node.range.end;
            match declarations.split_last() {
                None => {
                    linebreak_indented_into(so_far, next_indent(indent));
                }
                Some((last_declaration_node, declarations_before_last)) => {
                    for declaration_node in declarations_before_last {
                        linebreak_indented_into(so_far, next_indent(indent));
                        gren_syntax_comments_then_linebreak_indented_into(
                            so_far,
                            next_indent(indent),
                            gren_syntax_comments_in_range(
                                comments,
                                lsp_types::Range {
                                    start: previous_declaration_end,
                                    end: declaration_node.range.start,
                                },
                            ),
                        );
                        gren_syntax_let_declaration_into(
                            so_far,
                            next_indent(indent),
                            comments,
                            gren_syntax_node_as_ref(declaration_node),
                        );
                        so_far.push('\n');
                        previous_declaration_end = declaration_node.range.end;
                    }
                    linebreak_indented_into(so_far, next_indent(indent));
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        next_indent(indent),
                        gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: previous_declaration_end,
                                end: last_declaration_node.range.start,
                            },
                        ),
                    );
                    gren_syntax_let_declaration_into(
                        so_far,
                        next_indent(indent),
                        comments,
                        gren_syntax_node_as_ref(last_declaration_node),
                    );
                    previous_declaration_end = last_declaration_node.range.end;
                }
            }
            if let Some(in_keyword_range) = maybe_in_keyword_range {
                gren_syntax_comments_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: previous_declaration_end,
                            end: in_keyword_range.start,
                        },
                    ),
                );
            }
            linebreak_indented_into(so_far, indent);
            so_far.push_str("in");
            linebreak_indented_into(so_far, indent);
            if let Some(result_node) = maybe_result {
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent,
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: maybe_in_keyword_range
                                .map(|range| range.end)
                                .unwrap_or(previous_declaration_end),
                            end: result_node.range.start,
                        },
                    ),
                );
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    gren_syntax_node_unbox(result_node),
                );
            }
        }
        GrenSyntaxExpression::Array(elements) => {
            let comments: &[GrenSyntaxNode<GrenSyntaxComment>] =
                gren_syntax_comments_in_range(comments, expression_node.range);
            match elements.split_last() {
                None => {
                    if comments.is_empty() {
                        so_far.push_str("[]");
                    } else {
                        so_far.push('[');
                        gren_syntax_comments_into(so_far, indent + 1, comments);
                        linebreak_indented_into(so_far, indent);
                        so_far.push(']');
                    }
                }
                Some((last_element_node, elements_before_last)) => {
                    so_far.push_str("[ ");
                    let line_span: LineSpan =
                        gren_syntax_expression_line_span(comments, expression_node);
                    let mut previous_element_end: lsp_types::Position = expression_node.range.start;
                    for element_node in elements_before_last {
                        gren_syntax_comments_then_linebreak_indented_into(
                            so_far,
                            indent,
                            gren_syntax_comments_in_range(
                                comments,
                                lsp_types::Range {
                                    start: previous_element_end,
                                    end: element_node.range.start,
                                },
                            ),
                        );
                        gren_syntax_expression_not_parenthesized_into(
                            so_far,
                            indent + 2,
                            comments,
                            gren_syntax_node_as_ref(element_node),
                        );
                        if line_span == LineSpan::Multiple {
                            linebreak_indented_into(so_far, indent);
                        }
                        so_far.push_str(", ");
                        previous_element_end = element_node.range.end;
                    }
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        indent + 2,
                        gren_syntax_comments_in_range(
                            comments,
                            lsp_types::Range {
                                start: previous_element_end,
                                end: last_element_node.range.start,
                            },
                        ),
                    );
                    gren_syntax_expression_not_parenthesized_into(
                        so_far,
                        indent + 2,
                        comments,
                        gren_syntax_node_as_ref(last_element_node),
                    );
                    space_or_linebreak_indented_into(so_far, line_span, indent);
                    let comments_after_last_element = gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: last_element_node.range.end,
                            end: expression_node.range.end,
                        },
                    );
                    if !comments_after_last_element.is_empty() {
                        linebreak_indented_into(so_far, indent);
                        gren_syntax_comments_then_linebreak_indented_into(
                            so_far,
                            indent + 2,
                            comments_after_last_element,
                        );
                    }
                    so_far.push(']');
                }
            }
        }
        GrenSyntaxExpression::Negation(maybe_in_negation) => {
            so_far.push('-');
            if let Some(in_negation_node) = maybe_in_negation {
                if let Some(in_negation_innermost) = gren_syntax_expression_to_unparenthesized(
                    gren_syntax_node_unbox(in_negation_node),
                ) && let GrenSyntaxExpression::Negation(_) = in_negation_innermost.value
                {
                    // -(-...)
                    gren_syntax_expression_parenthesized_into(
                        so_far,
                        indent + 1,
                        comments,
                        in_negation_node.range,
                        Some(in_negation_innermost),
                    );
                } else {
                    gren_syntax_expression_parenthesized_if_space_separated_into(
                        so_far,
                        indent + 1,
                        comments,
                        gren_syntax_node_unbox(in_negation_node),
                    );
                }
            }
        }
        GrenSyntaxExpression::OperatorFunction(operator_node) => {
            so_far.push('(');
            so_far.push_str(operator_node.value);
            so_far.push(')');
        }
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens
                && let Some(innermost) =
                    gren_syntax_expression_to_unparenthesized(gren_syntax_node_unbox(in_parens))
            {
                let comments_before_innermost = gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: expression_node.range.start,
                        end: innermost.range.start,
                    },
                );
                let comments_after_innermost = gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: innermost.range.end,
                        end: expression_node.range.end,
                    },
                );
                if comments_before_innermost.is_empty() && comments_after_innermost.is_empty() {
                    gren_syntax_expression_not_parenthesized_into(
                        so_far, indent, comments, innermost,
                    );
                } else {
                    gren_syntax_expression_parenthesized_into(
                        so_far,
                        indent,
                        comments,
                        expression_node.range,
                        Some(innermost),
                    );
                }
            } else {
                gren_syntax_expression_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    expression_node.range,
                    None,
                );
            }
        }
        GrenSyntaxExpression::Record(fields) => match fields.split_first() {
            None => {
                let comments_in_curlies: &[GrenSyntaxNode<GrenSyntaxComment>] =
                    gren_syntax_comments_in_range(comments, expression_node.range);
                if comments_in_curlies.is_empty() {
                    so_far.push_str("{}");
                } else {
                    so_far.push('{');
                    gren_syntax_comments_into(so_far, indent + 1, comments);
                    linebreak_indented_into(so_far, indent);
                    so_far.push('}');
                }
            }
            Some((field0, field1_up)) => {
                let line_span: LineSpan =
                    gren_syntax_range_line_span(expression_node.range, comments);
                so_far.push_str("{ ");
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent + 2,
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: expression_node.range.start,
                            end: field0.name.range.start,
                        },
                    ),
                );
                let previous_syntax_end: lsp_types::Position =
                    gren_syntax_expression_fields_into_string(
                        so_far, indent, comments, line_span, field0, field1_up,
                    );
                space_or_linebreak_indented_into(so_far, line_span, indent);
                let comments_before_closing_curly = gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: previous_syntax_end,
                        end: expression_node.range.end,
                    },
                );
                if !comments_before_closing_curly.is_empty() {
                    linebreak_indented_into(so_far, indent);
                    gren_syntax_comments_then_linebreak_indented_into(
                        so_far,
                        indent,
                        comments_before_closing_curly,
                    );
                }
                so_far.push('}');
            }
        },
        GrenSyntaxExpression::RecordAccess {
            record,
            field: maybe_field,
        } => {
            gren_syntax_expression_parenthesized_if_space_separated_into(
                so_far,
                indent,
                comments,
                gren_syntax_node_unbox(record),
            );
            so_far.push('.');
            if let Some(field_name_node) = maybe_field {
                so_far.push_str(&field_name_node.value);
            }
        }
        GrenSyntaxExpression::RecordAccessFunction(maybe_field_name) => {
            so_far.push('.');
            if let Some(field_name_node) = maybe_field_name {
                so_far.push_str(&field_name_node.value);
            }
        }
        GrenSyntaxExpression::RecordUpdate {
            record_variable: maybe_record_variable,
            bar_key_symbol_range: _,
            fields,
        } => {
            let line_span: LineSpan = gren_syntax_range_line_span(expression_node.range, comments);
            so_far.push_str("{ ");
            let mut previous_syntax_end: lsp_types::Position = expression_node.range.start;
            if let Some(record_variable_node) = maybe_record_variable {
                so_far.push_str(&record_variable_node.value);
                previous_syntax_end = record_variable_node.range.end;
            }
            if let Some((field0, field1_up)) = fields.split_first() {
                space_or_linebreak_indented_into(so_far, line_span, indent);
                so_far.push_str("| ");
                previous_syntax_end = gren_syntax_expression_fields_into_string(
                    so_far, indent, comments, line_span, field0, field1_up,
                );
            }
            space_or_linebreak_indented_into(so_far, line_span, indent);
            let comments_before_closing_curly = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: expression_node.range.end,
                },
            );
            if !comments_before_closing_curly.is_empty() {
                linebreak_indented_into(so_far, indent);
                gren_syntax_comments_then_linebreak_indented_into(
                    so_far,
                    indent + 2,
                    comments_before_closing_curly,
                );
            }
            so_far.push('}');
        }
        GrenSyntaxExpression::Reference {
            qualification,
            name,
        } => {
            if qualification.is_empty() {
                so_far.push_str(name);
            } else {
                so_far.push_str(qualification);
                so_far.push('.');
                so_far.push_str(name);
            }
        }
        GrenSyntaxExpression::String {
            content,
            quoting_style,
        } => {
            gren_string_into(so_far, *quoting_style, content);
        }
    }
}
/// returns the last syntax end position
fn gren_syntax_case_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    previous_syntax_end: lsp_types::Position,
    case: &GrenSyntaxExpressionCase,
) -> lsp_types::Position {
    let before_case_arrow_key_symbol: lsp_types::Position = case
        .arrow_key_symbol_range
        .map(|range| range.end)
        .unwrap_or(case.pattern.range.end);
    gren_syntax_comments_then_linebreak_indented_into(
        so_far,
        indent,
        gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: previous_syntax_end,
                end: before_case_arrow_key_symbol,
            },
        ),
    );
    gren_syntax_pattern_not_parenthesized_into(so_far, gren_syntax_node_as_ref(&case.pattern));
    so_far.push_str(" ->");
    linebreak_indented_into(so_far, next_indent(indent));
    if let Some(result_node) = &case.result {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent),
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: before_case_arrow_key_symbol,
                    end: result_node.range.end,
                },
            ),
        );
        gren_syntax_expression_not_parenthesized_into(
            so_far,
            next_indent(indent),
            comments,
            gren_syntax_node_as_ref(result_node),
        );
        result_node.range.end
    } else {
        before_case_arrow_key_symbol
    }
}
/// returns the last syntax end position
fn gren_syntax_expression_fields_into_string<'a>(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    line_span: LineSpan,
    field0: &'a GrenSyntaxExpressionField,
    field1_up: &'a [GrenSyntaxExpressionField],
) -> lsp_types::Position {
    so_far.push_str(&field0.name.value);
    let mut previous_syntax_end: lsp_types::Position = field0.name.range.end;
    so_far.push_str(" =");
    if let Some(field0_value_node) = &field0.value {
        let comments_before_field0_value = gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: field0.name.range.end,
                end: field0_value_node.range.start,
            },
        );
        space_or_linebreak_indented_into(
            so_far,
            if comments_before_field0_value.is_empty() {
                gren_syntax_expression_line_span(
                    comments,
                    gren_syntax_node_as_ref(field0_value_node),
                )
            } else {
                LineSpan::Multiple
            },
            next_indent(indent + 2),
        );
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent + 2),
            comments_before_field0_value,
        );
        gren_syntax_expression_not_parenthesized_into(
            so_far,
            next_indent(indent + 2),
            comments,
            gren_syntax_node_as_ref(field0_value_node),
        );
        previous_syntax_end = field0_value_node.range.end;
    }
    for field in field1_up {
        if line_span == LineSpan::Multiple {
            linebreak_indented_into(so_far, indent);
        }
        so_far.push_str(", ");
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            indent + 2,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: field.name.range.start,
                },
            ),
        );
        so_far.push_str(&field.name.value);
        previous_syntax_end = field.name.range.end;
        so_far.push_str(" =");
        if let Some(field_value_node) = &field.value {
            let comments_before_field_value = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: field.name.range.end,
                    end: field_value_node.range.start,
                },
            );
            space_or_linebreak_indented_into(
                so_far,
                if comments_before_field_value.is_empty() {
                    gren_syntax_range_line_span(
                        lsp_types::Range {
                            start: field.name.range.end,
                            end: field_value_node.range.end,
                        },
                        comments,
                    )
                } else {
                    LineSpan::Multiple
                },
                next_indent(indent + 2),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                next_indent(indent + 2),
                comments_before_field_value,
            );
            gren_syntax_expression_not_parenthesized_into(
                so_far,
                next_indent(indent + 2),
                comments,
                gren_syntax_node_as_ref(field_value_node),
            );
            previous_syntax_end = field_value_node.range.end;
        }
    }
    previous_syntax_end
}
fn gren_syntax_let_declaration_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    let_declaration_node: GrenSyntaxNode<&GrenSyntaxLetDeclaration>,
) {
    match let_declaration_node.value {
        GrenSyntaxLetDeclaration::Destructuring {
            pattern: pattern_node,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            expression: maybe_expression,
        } => {
            gren_syntax_comments_into(
                so_far,
                indent,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: let_declaration_node.range.start,
                        end: maybe_equals_key_symbol_range
                            .map(|range| range.start)
                            .unwrap_or(pattern_node.range.end),
                    },
                ),
            );
            gren_syntax_pattern_parenthesized_if_space_separated_into(
                so_far,
                gren_syntax_node_as_ref(pattern_node),
            );
            so_far.push_str(" =");
            linebreak_indented_into(so_far, next_indent(indent));
            if let Some(expression_node) = maybe_expression {
                gren_syntax_comments_into(
                    so_far,
                    next_indent(indent),
                    gren_syntax_comments_in_range(
                        comments,
                        lsp_types::Range {
                            start: maybe_equals_key_symbol_range
                                .map(|range| range.end)
                                .unwrap_or(pattern_node.range.end),
                            end: expression_node.range.end,
                        },
                    ),
                );
            }
        }
        GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        } => {
            gren_syntax_variable_declaration_into(
                so_far,
                indent,
                comments,
                gren_syntax_node_unbox(start_name_node),
                maybe_signature.as_ref(),
                parameters,
                *maybe_equals_key_symbol_range,
                maybe_result.as_ref().map(gren_syntax_node_as_ref),
            );
        }
    }
}
fn gren_syntax_variable_declaration_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    start_name_node: GrenSyntaxNode<&str>,
    maybe_signature: Option<&GrenSyntaxVariableDeclarationSignature>,
    parameters: &[GrenSyntaxNode<GrenSyntaxPattern>],
    maybe_equals_key_symbol_range: Option<lsp_types::Range>,
    maybe_result: Option<GrenSyntaxNode<&GrenSyntaxExpression>>,
) {
    so_far.push_str(start_name_node.value);
    let mut syntax_before_parameters_end: lsp_types::Position = start_name_node.range.end;
    if let Some(signature) = maybe_signature {
        so_far.push_str(" :");
        if let Some(type_node) = &signature.type_ {
            let comments_before_type = gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: start_name_node.range.end,
                    end: type_node.range.start,
                },
            );
            space_or_linebreak_indented_into(
                so_far,
                if start_name_node.range.end.line == type_node.range.end.line
                    && comments_before_type.is_empty()
                {
                    LineSpan::Single
                } else {
                    LineSpan::Multiple
                },
                next_indent(indent),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                next_indent(indent),
                comments_before_type,
            );
            gren_syntax_type_not_parenthesized_into(
                so_far,
                next_indent(indent),
                |qualified| qualified.qualification,
                comments,
                gren_syntax_node_as_ref(type_node),
            );
            syntax_before_parameters_end = type_node.range.end;
        }
        linebreak_indented_into(so_far, indent);
        if let Some(implementation_name_range) = signature.implementation_name_range {
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: signature
                            .type_
                            .as_ref()
                            .map(|node| node.range.end)
                            .unwrap_or(signature.colon_key_symbol_range.end),
                        end: implementation_name_range.start,
                    },
                ),
            );
            syntax_before_parameters_end = implementation_name_range.end;
        }
        so_far.push_str(start_name_node.value);
    }
    let parameter_comments: &[GrenSyntaxNode<GrenSyntaxComment>] = gren_syntax_comments_in_range(
        comments,
        lsp_types::Range {
            start: syntax_before_parameters_end,
            end: if maybe_result.is_none()
                && let Some(equals_key_symbol_range) = maybe_equals_key_symbol_range
            {
                equals_key_symbol_range.end
            } else {
                parameters
                    .last()
                    .map(|node| node.range.end)
                    .unwrap_or(syntax_before_parameters_end)
            },
        },
    );
    let parameters_line_span: LineSpan = if parameter_comments.is_empty() {
        LineSpan::Single
    } else {
        LineSpan::Multiple
    };
    let mut previous_parameter_end: lsp_types::Position = start_name_node.range.start;
    for parameter_node in parameters {
        space_or_linebreak_indented_into(so_far, parameters_line_span, next_indent(indent));
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent),
            gren_syntax_comments_in_range(
                parameter_comments,
                lsp_types::Range {
                    start: previous_parameter_end,
                    end: parameter_node.range.start,
                },
            ),
        );
        gren_syntax_pattern_parenthesized_if_space_separated_into(
            so_far,
            gren_syntax_node_as_ref(parameter_node),
        );
        previous_parameter_end = parameter_node.range.end;
    }
    space_or_linebreak_indented_into(so_far, parameters_line_span, next_indent(indent));
    if maybe_result.is_none()
        && let Some(equals_key_symbol_range) = maybe_equals_key_symbol_range
        && let comments_before_equals_key_symbol = gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: previous_parameter_end,
                end: equals_key_symbol_range.start,
            },
        )
        && !comments_before_equals_key_symbol.is_empty()
    {
        linebreak_indented_into(so_far, indent);
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent),
            comments_before_equals_key_symbol,
        );
    }
    so_far.push('=');
    linebreak_indented_into(so_far, next_indent(indent));
    if let Some(result_node) = maybe_result {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            next_indent(indent),
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_parameter_end,
                    end: result_node.range.start,
                },
            ),
        );
        gren_syntax_expression_not_parenthesized_into(
            so_far,
            next_indent(indent),
            comments,
            result_node,
        );
    }
}
fn gren_syntax_expression_to_unparenthesized(
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) -> Option<GrenSyntaxNode<&GrenSyntaxExpression>> {
    match expression_node.value {
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => match maybe_in_parens {
            None => None,
            Some(in_parens) => {
                gren_syntax_expression_to_unparenthesized(gren_syntax_node_unbox(in_parens))
            }
        },
        _ => Some(expression_node),
    }
}
fn gren_syntax_range_line_span(
    range: lsp_types::Range,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
) -> LineSpan {
    if gren_syntax_comments_in_range(comments, range).is_empty()
        && range.start.line == range.end.line
    {
        LineSpan::Single
    } else {
        LineSpan::Multiple
    }
}
/// A more accurate (but probably slower) alternative:
/// ```rust
/// let so_far_length_before = so_far.len();
/// ...into(so_far, ...);
/// if so_far[so_far_length_before..].contains('\n') {
///     so_far.insert_str(so_far_length_before, ..linebreak indented..);
/// } else {
///     so_far.insert(so_far_length_before, ' ');
/// }
/// ```
/// with a potential optimization being
fn gren_syntax_expression_line_span(
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) -> LineSpan {
    if gren_syntax_comments_in_range(comments, expression_node.range).is_empty()
        && expression_node.range.start.line == expression_node.range.end.line
        && !gren_syntax_expression_any_sub(expression_node, |sub_node| match sub_node.value {
            GrenSyntaxExpression::CaseOf { .. } => true,
            GrenSyntaxExpression::IfThenElse { .. } => true,
            GrenSyntaxExpression::LetIn { .. } => true,
            GrenSyntaxExpression::String {
                content,
                quoting_style,
            } => {
                *quoting_style == GrenSyntaxStringQuotingStyle::TripleQuoted
                    && content.contains('\n')
            }
            GrenSyntaxExpression::Integer { .. }
            | GrenSyntaxExpression::Float(_)
            | GrenSyntaxExpression::Char(_)
            | GrenSyntaxExpression::Negation(_)
            | GrenSyntaxExpression::Parenthesized(_)
            | GrenSyntaxExpression::Array(_)
            | GrenSyntaxExpression::Lambda { .. }
            | GrenSyntaxExpression::InfixOperationIgnoringPrecedence { .. }
            | GrenSyntaxExpression::Record(_)
            | GrenSyntaxExpression::RecordUpdate { .. }
            | GrenSyntaxExpression::RecordAccess { .. }
            | GrenSyntaxExpression::RecordAccessFunction(_)
            | GrenSyntaxExpression::Reference { .. }
            | GrenSyntaxExpression::OperatorFunction(_)
            | GrenSyntaxExpression::Call { .. } => false,
        })
    {
        LineSpan::Single
    } else {
        LineSpan::Multiple
    }
}
fn gren_syntax_expression_parenthesized_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    full_range: lsp_types::Range,
    maybe_innermost: Option<GrenSyntaxNode<&GrenSyntaxExpression>>,
) {
    so_far.push('(');
    let start_so_far_length: usize = so_far.len();
    match maybe_innermost {
        None => {
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(comments, full_range),
            );
        }
        Some(innermost) => {
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: full_range.start,
                        end: innermost.range.start,
                    },
                ),
            );
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                indent + 1,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: innermost.range.end,
                        end: full_range.end,
                    },
                ),
            );
            gren_syntax_expression_not_parenthesized_into(so_far, indent + 1, comments, innermost);
        }
    }
    if so_far[start_so_far_length..].contains('\n') {
        linebreak_indented_into(so_far, indent);
    }
    so_far.push(')');
}
fn gren_syntax_expression_parenthesized_if_space_separated_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) {
    match gren_syntax_expression_to_unparenthesized(expression_node) {
        None => {
            gren_syntax_expression_parenthesized_into(
                so_far,
                indent,
                comments,
                expression_node.range,
                None,
            );
        }
        Some(unparenthesized) => {
            let is_space_separated: bool = match unparenthesized.value {
                GrenSyntaxExpression::IfThenElse { .. }
                | GrenSyntaxExpression::Lambda { .. }
                | GrenSyntaxExpression::LetIn { .. }
                | GrenSyntaxExpression::InfixOperationIgnoringPrecedence { .. }
                | GrenSyntaxExpression::Call { .. }
                | GrenSyntaxExpression::CaseOf { .. } => true,
                GrenSyntaxExpression::Char(_)
                | GrenSyntaxExpression::Float(_)
                | GrenSyntaxExpression::Integer { .. }
                | GrenSyntaxExpression::Array(_)
                | GrenSyntaxExpression::Negation(_)
                | GrenSyntaxExpression::OperatorFunction(_)
                | GrenSyntaxExpression::Parenthesized(_)
                | GrenSyntaxExpression::Record(_)
                | GrenSyntaxExpression::RecordAccess { .. }
                | GrenSyntaxExpression::RecordAccessFunction(_)
                | GrenSyntaxExpression::RecordUpdate { .. }
                | GrenSyntaxExpression::Reference { .. }
                | GrenSyntaxExpression::String { .. } => false,
            };
            if is_space_separated {
                gren_syntax_expression_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    expression_node.range,
                    Some(unparenthesized),
                );
            } else {
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    expression_node,
                );
            }
        }
    }
}
fn gren_syntax_expression_parenthesized_if_not_call_but_space_separated_into(
    so_far: &mut String,
    indent: usize,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) {
    match gren_syntax_expression_to_unparenthesized(expression_node) {
        None => {
            gren_syntax_expression_parenthesized_into(
                so_far,
                indent,
                comments,
                expression_node.range,
                None,
            );
        }
        Some(unparenthesized) => {
            let is_space_separated: bool = match unparenthesized.value {
                GrenSyntaxExpression::IfThenElse { .. }
                | GrenSyntaxExpression::Lambda { .. }
                | GrenSyntaxExpression::LetIn { .. }
                | GrenSyntaxExpression::InfixOperationIgnoringPrecedence { .. }
                | GrenSyntaxExpression::CaseOf { .. } => true,
                GrenSyntaxExpression::Call { .. }
                | GrenSyntaxExpression::Char(_)
                | GrenSyntaxExpression::Float(_)
                | GrenSyntaxExpression::Integer { .. }
                | GrenSyntaxExpression::Array(_)
                | GrenSyntaxExpression::Negation(_)
                | GrenSyntaxExpression::OperatorFunction(_)
                | GrenSyntaxExpression::Parenthesized(_)
                | GrenSyntaxExpression::Record(_)
                | GrenSyntaxExpression::RecordAccess { .. }
                | GrenSyntaxExpression::RecordAccessFunction(_)
                | GrenSyntaxExpression::RecordUpdate { .. }
                | GrenSyntaxExpression::Reference { .. }
                | GrenSyntaxExpression::String { .. } => false,
            };
            if is_space_separated {
                gren_syntax_expression_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    expression_node.range,
                    Some(unparenthesized),
                );
            } else {
                gren_syntax_expression_not_parenthesized_into(
                    so_far,
                    indent,
                    comments,
                    expression_node,
                );
            }
        }
    }
}
fn gren_syntax_expression_any_sub(
    expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
    is_needle: impl Fn(GrenSyntaxNode<&GrenSyntaxExpression>) -> bool + Copy,
) -> bool {
    if is_needle(expression_node) {
        return true;
    }
    match expression_node.value {
        GrenSyntaxExpression::Call {
            called,
            argument0,
            argument1_up,
        } => {
            gren_syntax_expression_any_sub(gren_syntax_node_unbox(called), is_needle)
                || gren_syntax_expression_any_sub(gren_syntax_node_unbox(argument0), is_needle)
                || argument1_up.iter().any(|argument_node| {
                    gren_syntax_expression_any_sub(
                        gren_syntax_node_as_ref(argument_node),
                        is_needle,
                    )
                })
        }
        GrenSyntaxExpression::CaseOf {
            matched: maybe_matched,
            of_keyword_range: _,
            cases,
        } => {
            maybe_matched.as_ref().is_some_and(|matched_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(matched_node), is_needle)
            }) || cases
                .iter()
                .filter_map(|case| case.result.as_ref())
                .any(|case_result_node| {
                    gren_syntax_expression_any_sub(
                        gren_syntax_node_as_ref(case_result_node),
                        is_needle,
                    )
                })
        }
        GrenSyntaxExpression::Char(_) => false,
        GrenSyntaxExpression::Float(_) => false,
        GrenSyntaxExpression::IfThenElse {
            condition: maybe_condition,
            then_keyword_range: _,
            on_true: maybe_on_true,
            else_keyword_range: _,
            on_false: maybe_on_false,
        } => {
            maybe_condition.as_ref().is_some_and(|condition_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(condition_node), is_needle)
            }) || maybe_on_true.as_ref().is_some_and(|on_true_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(on_true_node), is_needle)
            }) || maybe_on_false.as_ref().is_some_and(|on_false_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(on_false_node), is_needle)
            })
        }
        GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
            left,
            operator: _,
            right: maybe_right,
        } => {
            gren_syntax_expression_any_sub(gren_syntax_node_unbox(left), is_needle)
                || maybe_right.as_ref().is_some_and(|right_node| {
                    gren_syntax_expression_any_sub(gren_syntax_node_unbox(right_node), is_needle)
                })
        }
        GrenSyntaxExpression::Integer { .. } => false,
        GrenSyntaxExpression::Lambda {
            parameters: _,
            arrow_key_symbol_range: _,
            result: maybe_result,
        } => maybe_result.as_ref().is_some_and(|result_node| {
            gren_syntax_expression_any_sub(gren_syntax_node_unbox(result_node), is_needle)
        }),
        GrenSyntaxExpression::LetIn {
            declarations,
            in_keyword_range: _,
            result: maybe_result,
        } => {
            maybe_result.as_ref().is_some_and(|result_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(result_node), is_needle)
            }) || declarations
                .iter()
                .filter_map(|declaration_node| match &declaration_node.value {
                    GrenSyntaxLetDeclaration::Destructuring {
                        pattern: _,
                        equals_key_symbol_range: _,
                        expression,
                    } => expression.as_ref(),
                    GrenSyntaxLetDeclaration::VariableDeclaration {
                        start_name: _,
                        signature: _,
                        parameters: _,
                        equals_key_symbol_range: _,
                        result,
                    } => result.as_ref(),
                })
                .any(|declaration_expression_node| {
                    gren_syntax_expression_any_sub(
                        gren_syntax_node_as_ref(declaration_expression_node),
                        is_needle,
                    )
                })
        }
        GrenSyntaxExpression::Array(elements) => elements.iter().any(|element_node| {
            gren_syntax_expression_any_sub(gren_syntax_node_as_ref(element_node), is_needle)
        }),
        GrenSyntaxExpression::Negation(maybe_in_negation) => {
            maybe_in_negation.as_ref().is_some_and(|in_negation| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(in_negation), is_needle)
            })
        }
        GrenSyntaxExpression::OperatorFunction(_) => false,
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => {
            maybe_in_parens.as_ref().is_some_and(|in_parens| {
                gren_syntax_expression_any_sub(gren_syntax_node_unbox(in_parens), is_needle)
            })
        }
        GrenSyntaxExpression::Record(fields) => fields
            .iter()
            .filter_map(|field| field.value.as_ref())
            .any(|field_value_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_as_ref(field_value_node), is_needle)
            }),
        GrenSyntaxExpression::RecordAccess { record, field: _ } => {
            gren_syntax_expression_any_sub(gren_syntax_node_unbox(record), is_needle)
        }
        GrenSyntaxExpression::RecordAccessFunction(_) => false,
        GrenSyntaxExpression::RecordUpdate {
            record_variable: _,
            bar_key_symbol_range: _,
            fields,
        } => fields
            .iter()
            .filter_map(|field| field.value.as_ref())
            .any(|field_value_node| {
                gren_syntax_expression_any_sub(gren_syntax_node_as_ref(field_value_node), is_needle)
            }),
        GrenSyntaxExpression::Reference { .. } => false,
        GrenSyntaxExpression::String { .. } => false,
    }
}
fn gren_syntax_module_format(module_state: &ModuleState) -> String {
    let gren_syntax_module: &GrenSyntaxModule = &module_state.syntax;
    let mut builder: String = String::with_capacity(module_state.source.len());
    let mut previous_syntax_end: lsp_types::Position;
    match &gren_syntax_module.header {
        None => {
            builder.push_str("module  exposing ()");
            previous_syntax_end = lsp_types::Position {
                line: 0,
                character: 0,
            }
        }
        Some(module_header) => {
            previous_syntax_end = gren_syntax_module_header_into(
                &mut builder,
                &gren_syntax_module.comments,
                module_header,
            );
        }
    }
    builder.push_str("\n\n");
    if let Some(module_documentation_node) = &gren_syntax_module.documentation {
        gren_syntax_module_level_comments(
            &mut builder,
            gren_syntax_comments_in_range(
                &gren_syntax_module.comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: module_documentation_node.range.start,
                },
            ),
        );
        gren_syntax_module_documentation_comment_into(
            &mut builder,
            &module_documentation_node.value,
        );
        builder.push_str("\n\n");
        previous_syntax_end = module_documentation_node.range.end;
    }
    if let Some(last_import_node) = gren_syntax_module.imports.last() {
        gren_syntax_module_level_comments(
            &mut builder,
            gren_syntax_comments_in_range(
                &gren_syntax_module.comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: last_import_node.range.end,
                },
            ),
        );
        gren_syntax_imports_then_linebreak_into(&mut builder, &gren_syntax_module.imports);
        previous_syntax_end = last_import_node.range.end;
    } else {
        builder.push('\n');
    }
    for documented_declaration_or_err in &gren_syntax_module.declarations {
        match documented_declaration_or_err {
            Err(whatever) => {
                builder.push_str(whatever);
            }
            Ok(documented_declaration) => {
                builder.push_str("\n\n");
                if let Some(module_documentation_node) = &documented_declaration.documentation {
                    gren_syntax_module_level_comments(
                        &mut builder,
                        gren_syntax_comments_in_range(
                            &gren_syntax_module.comments,
                            lsp_types::Range {
                                start: previous_syntax_end,
                                end: module_documentation_node.range.start,
                            },
                        ),
                    );
                    gren_syntax_documentation_comment_then_linebreak_into(
                        &mut builder,
                        &module_documentation_node.value,
                    );
                    previous_syntax_end = module_documentation_node.range.end;
                }
                if let Some(declaration_node) = &documented_declaration.declaration {
                    gren_syntax_module_level_comments(
                        &mut builder,
                        gren_syntax_comments_in_range(
                            &gren_syntax_module.comments,
                            lsp_types::Range {
                                start: previous_syntax_end,
                                end: declaration_node.range.start,
                            },
                        ),
                    );
                    gren_syntax_declaration_into(
                        &mut builder,
                        &gren_syntax_module.comments,
                        gren_syntax_node_as_ref(declaration_node),
                    );
                    previous_syntax_end = declaration_node.range.end;
                    builder.push('\n');
                }
            }
        }
    }
    let comments_after_declarations: &[GrenSyntaxNode<GrenSyntaxComment>] =
        gren_syntax_comments_from_position(&gren_syntax_module.comments, previous_syntax_end);
    if !comments_after_declarations.is_empty() {
        builder.push_str("\n\n\n");
        gren_syntax_comments_then_linebreak_indented_into(
            &mut builder,
            0,
            comments_after_declarations,
        );
    }
    builder
}
fn gren_syntax_module_level_comments(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
) {
    if !comments.is_empty() {
        so_far.push('\n');
        gren_syntax_comments_then_linebreak_indented_into(so_far, 0, comments);
        so_far.push_str("\n\n");
    }
}
fn gren_syntax_module_documentation_comment_into(
    so_far: &mut String,
    module_documentation_elements: &[GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
) {
    so_far.push_str("{-|");
    for module_documentation_element in module_documentation_elements {
        match &module_documentation_element.value {
            GrenSyntaxModuleDocumentationElement::Markdown(markdown_node) => {
                so_far.push_str(markdown_node);
            }
            GrenSyntaxModuleDocumentationElement::AtDocs(expose_group_names) => {
                so_far.push_str("@docs ");
                if let Some((expose_name0_node, expose_name1_up)) = expose_group_names.split_first()
                {
                    so_far.push_str(
                        expose_name0_node
                            .value
                            .strip_suffix("(..)")
                            .unwrap_or(&expose_name0_node.value),
                    );
                    for expose_name_node in expose_name1_up {
                        so_far.push_str(", ");
                        so_far.push_str(
                            expose_name_node
                                .value
                                .strip_suffix("(..)")
                                .unwrap_or(&expose_name_node.value),
                        );
                    }
                }
            }
        }
    }
    so_far.push_str("-}");
}
fn gren_syntax_documentation_comment_then_linebreak_into(so_far: &mut String, content: &str) {
    so_far.push_str("{-|");
    so_far.push_str(content);
    so_far.push_str("-}\n");
}
/// returns the last syntax end position
fn gren_syntax_module_header_into(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    gren_syntax_module_header: &GrenSyntaxModuleHeader,
) -> lsp_types::Position {
    let before_exposing: lsp_types::Position = gren_syntax_module_header
        .exposing_keyword_range
        .map(|range| range.start)
        .unwrap_or_else(|| match &gren_syntax_module_header.specific {
            GrenSyntaxModuleHeaderSpecific::Pure {
                module_keyword_range,
            } => match &gren_syntax_module_header.module_name {
                Some(module_name_node) => module_name_node.range.end,
                None => module_keyword_range.end,
            },
            GrenSyntaxModuleHeaderSpecific::Port {
                port_keyword_range: _,
                module_keyword_range,
            } => match &gren_syntax_module_header.module_name {
                Some(module_name_node) => module_name_node.range.end,
                None => module_keyword_range.end,
            },
            GrenSyntaxModuleHeaderSpecific::Effect {
                effect_keyword_range: _,
                module_keyword_range: _,
                where_keyword_range,
                command: maybe_command,
                subscription: maybe_subscription,
            } => match (maybe_command, maybe_subscription) {
                (_, Some(subscription_entry)) => subscription_entry.value_type_name.range.end,
                (Some(command_entry), None) => command_entry.value_type_name.range.end,
                (None, None) => where_keyword_range.end,
            },
        });
    gren_syntax_comments_then_linebreak_indented_into(
        so_far,
        0,
        gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: lsp_types::Position {
                    line: 0,
                    character: 0,
                },
                end: before_exposing,
            },
        ),
    );
    match &gren_syntax_module_header.specific {
        GrenSyntaxModuleHeaderSpecific::Pure {
            module_keyword_range: _,
        } => {
            so_far.push_str("module ");
            if let Some(module_name_node) = &gren_syntax_module_header.module_name {
                so_far.push_str(&module_name_node.value);
            }
        }
        GrenSyntaxModuleHeaderSpecific::Port {
            port_keyword_range: _,
            module_keyword_range: _,
        } => {
            so_far.push_str("port module ");
            if let Some(module_name_node) = &gren_syntax_module_header.module_name {
                so_far.push_str(&module_name_node.value);
            }
        }
        GrenSyntaxModuleHeaderSpecific::Effect {
            effect_keyword_range: _,
            module_keyword_range: _,
            where_keyword_range: _,
            command: maybe_command,
            subscription: maybe_subscription,
        } => {
            so_far.push_str("effect module ");
            if let Some(module_name_node) = &gren_syntax_module_header.module_name {
                so_far.push_str(&module_name_node.value);
            }
            so_far.push_str(" where { ");
            match (maybe_command, maybe_subscription) {
                (None, Some(subscription_entry)) => {
                    so_far.push_str("subscription = ");
                    so_far.push_str(&subscription_entry.value_type_name.value);
                }
                (Some(command_entry), None) => {
                    so_far.push_str("command = ");
                    so_far.push_str(&command_entry.value_type_name.value);
                }
                (Some(command_entry), Some(subscription_entry)) => {
                    so_far.push_str("command = ");
                    so_far.push_str(&command_entry.value_type_name.value);
                    so_far.push_str(", subscription = ");
                    so_far.push_str(&subscription_entry.value_type_name.value);
                }
                (None, None) => {}
            }
            so_far.push_str(" }");
        }
    }
    so_far.push_str(" exposing ");
    match &gren_syntax_module_header.exposing {
        Some(module_header_exposing_node) => {
            // respect @docs grouping like elm-format does?
            gren_syntax_exposing_into(so_far, &module_header_exposing_node.value);
            module_header_exposing_node.range.end
        }
        None => {
            so_far.push_str("()");
            gren_syntax_module_header
                .exposing_keyword_range
                .map(|range| range.end)
                .unwrap_or(before_exposing)
        }
    }
}
fn gren_syntax_exposing_into(so_far: &mut String, gren_syntax_exposing: &GrenSyntaxExposing) {
    match gren_syntax_exposing {
        GrenSyntaxExposing::All(_) => {
            so_far.push_str("(..)");
        }
        GrenSyntaxExposing::Explicit(exposes) => {
            so_far.push('(');
            let mut expose_strings: std::collections::BTreeSet<std::borrow::Cow<str>> =
                std::collections::BTreeSet::new();
            gren_syntax_exposes_into_expose_strings(&mut expose_strings, exposes);
            let mut expose_strings_iterator = expose_strings.into_iter();
            if let Some(expose_string0) = expose_strings_iterator.next() {
                so_far.push_str(&expose_string0);
                for expose_string in expose_strings_iterator {
                    so_far.push_str(", ");
                    so_far.push_str(&expose_string);
                }
            }
            so_far.push(')');
        }
    }
}
fn gren_syntax_imports_then_linebreak_into(
    so_far: &mut String,
    imports: &[GrenSyntaxNode<GrenSyntaxImport>],
) {
    if imports.is_empty() {
        return;
    }
    let mut imports_without_module_name: Vec<&GrenSyntaxNode<GrenSyntaxImport>> = Vec::new();
    let mut imports_with_module_name_merged: std::collections::BTreeMap<
        &str,
        GrenImportOfModuleNameSummary,
    > = std::collections::BTreeMap::new();
    for import_node in imports {
        match &import_node.value.module_name {
            Some(import_module_name_node) => {
                imports_with_module_name_merged
                    .entry(&import_module_name_node.value)
                    .and_modify(|existing_import_with_same_module_name_summary| {
                        gren_syntax_import_merge_into_summary(
                            existing_import_with_same_module_name_summary,
                            &import_node.value,
                        );
                    })
                    .or_insert_with(|| gren_syntax_import_merge_to_summary(&import_node.value));
            }
            None => {
                imports_without_module_name.push(import_node);
            }
        }
    }
    for (import_module_name, import_of_module_name_summary) in imports_with_module_name_merged {
        let mut import_aliases_iterator = import_of_module_name_summary.aliases.into_iter();
        if import_of_module_name_summary.alias_required
            && let Some(alias0) = import_aliases_iterator.next()
        {
            so_far.push_str("import ");
            so_far.push_str(import_module_name);
            so_far.push_str(" as ");
            so_far.push_str(alias0);
        } else {
            so_far.push_str("import ");
            so_far.push_str(import_module_name);
        }
        match import_of_module_name_summary.exposing {
            GrenExposingStrings::All => {
                so_far.push_str(" exposing (..)");
            }
            GrenExposingStrings::Explicit(expose_strings) => {
                if !expose_strings.is_empty() {
                    so_far.push_str(" exposing (");
                    let mut expose_strings_iterator = expose_strings.into_iter();
                    if let Some(expose_string0) = expose_strings_iterator.next() {
                        so_far.push_str(&expose_string0);
                        for expose_string in expose_strings_iterator {
                            so_far.push_str(", ");
                            so_far.push_str(&expose_string);
                        }
                    }
                    so_far.push(')');
                }
            }
        }
        so_far.push('\n');
        for import_alias in import_aliases_iterator {
            so_far.push_str("import ");
            so_far.push_str(import_module_name);
            so_far.push_str(" as ");
            so_far.push_str(import_alias);
            so_far.push('\n');
        }
    }
    for import_without_module_name_node in imports_without_module_name {
        so_far.push_str("import ");
        if let Some(import_alias_name_node) = &import_without_module_name_node.value.alias_name {
            so_far.push_str(" as ");
            so_far.push_str(&import_alias_name_node.value);
        } else if import_without_module_name_node
            .value
            .as_keyword_range
            .is_some()
        {
            so_far.push_str(" as ");
        }
        if import_without_module_name_node
            .value
            .exposing_keyword_range
            .is_some()
            || import_without_module_name_node.value.exposing.is_some()
        {
            so_far.push_str(" exposing ");
            match &import_without_module_name_node.value.exposing {
                None => {
                    so_far.push_str("()");
                }
                Some(import_exposing_node) => {
                    gren_syntax_exposing_into(so_far, &import_exposing_node.value);
                }
            }
        }
        so_far.push('\n');
    }
}
struct GrenImportOfModuleNameSummary<'a> {
    alias_required: bool,
    aliases: std::collections::BTreeSet<&'a str>,
    exposing: GrenExposingStrings<'a>,
}
enum GrenExposingStrings<'a> {
    All,
    Explicit(std::collections::BTreeSet<std::borrow::Cow<'a, str>>),
}
fn gren_syntax_import_merge_to_summary<'a>(
    gren_syntax_import: &'a GrenSyntaxImport,
) -> GrenImportOfModuleNameSummary<'a> {
    GrenImportOfModuleNameSummary {
        alias_required: gren_syntax_import.alias_name.is_some(),
        aliases: match &gren_syntax_import.alias_name {
            None => std::collections::BTreeSet::new(),
            Some(import_alias_name_node) => {
                std::collections::BTreeSet::from([import_alias_name_node.value.as_ref()])
            }
        },
        exposing: match &gren_syntax_import.exposing {
            None => GrenExposingStrings::Explicit(std::collections::BTreeSet::new()),
            Some(import_exposing) => match &import_exposing.value {
                GrenSyntaxExposing::All(_) => GrenExposingStrings::All,
                GrenSyntaxExposing::Explicit(exposes) => {
                    let mut expose_strings: std::collections::BTreeSet<std::borrow::Cow<str>> =
                        std::collections::BTreeSet::new();
                    gren_syntax_exposes_into_expose_strings(&mut expose_strings, exposes);
                    GrenExposingStrings::Explicit(expose_strings)
                }
            },
        },
    }
}
fn gren_syntax_import_merge_into_summary<'a>(
    summary_to_merge_with: &mut GrenImportOfModuleNameSummary<'a>,
    gren_syntax_import: &'a GrenSyntaxImport,
) {
    match &gren_syntax_import.alias_name {
        None => {
            summary_to_merge_with.alias_required = false;
        }
        Some(import_alias_name_node) => {
            summary_to_merge_with
                .aliases
                .insert(import_alias_name_node.value.as_ref());
        }
    }
    match (
        &mut summary_to_merge_with.exposing,
        gren_syntax_import.exposing.as_ref().map(|node| &node.value),
    ) {
        (GrenExposingStrings::All, _) => {}
        (_, None) => {}
        (GrenExposingStrings::Explicit(_), Some(GrenSyntaxExposing::All(_))) => {
            summary_to_merge_with.exposing = GrenExposingStrings::All;
        }
        (
            GrenExposingStrings::Explicit(expose_strings_to_merge_with),
            Some(GrenSyntaxExposing::Explicit(import_exposes)),
        ) => {
            gren_syntax_exposes_into_expose_strings(expose_strings_to_merge_with, import_exposes);
        }
    }
}

fn gren_syntax_exposes_into_expose_strings<'a>(
    expose_strings_so_far: &mut std::collections::BTreeSet<std::borrow::Cow<'a, str>>,
    exposes: &'a [GrenSyntaxNode<GrenSyntaxExpose>],
) {
    for expose_node in exposes {
        match &expose_node.value {
            GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                name: name_node,
                open_range: _,
            } => {
                expose_strings_so_far
                    .insert(std::borrow::Cow::Owned(format!("{}(..)", name_node.value)));
            }
            GrenSyntaxExpose::Operator(None) => {}
            GrenSyntaxExpose::Operator(Some(operator_node)) => {
                expose_strings_so_far.insert(std::borrow::Cow::Owned(format!(
                    "({})",
                    operator_node.value
                )));
            }
            GrenSyntaxExpose::Type(name) => {
                expose_strings_so_far.insert(std::borrow::Cow::Borrowed(name));
            }
            GrenSyntaxExpose::Variable(name) => {
                expose_strings_so_far.insert(std::borrow::Cow::Borrowed(name));
            }
        }
    }
}
fn gren_syntax_declaration_into(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    declaration_node: GrenSyntaxNode<&GrenSyntaxDeclaration>,
) {
    match declaration_node.value {
        GrenSyntaxDeclaration::ChoiceType {
            name: maybe_name,
            parameters,
            equals_key_symbol_range: _,
            variant0_name: maybe_variant0_name,
            variant0_value: variant0_maybe_value,
            variant1_up,
        } => {
            gren_syntax_choice_type_declaration_into(
                so_far,
                comments,
                |qualified| qualified.qualification,
                declaration_node.range,
                maybe_name.as_ref().map(gren_syntax_node_unbox),
                parameters,
                maybe_variant0_name.as_ref().map(gren_syntax_node_unbox),
                variant0_maybe_value.as_ref().map(gren_syntax_node_as_ref),
                variant1_up,
            );
        }
        GrenSyntaxDeclaration::Operator {
            direction: maybe_infix_direction,
            precedence: maybe_infix_precedence,
            operator: maybe_operator,
            equals_key_symbol_range: _,
            function: maybe_implementation_function_name,
        } => {
            so_far.push_str("infix ");
            if let Some(infix_direction_node) = maybe_infix_direction {
                so_far.push_str(gren_syntax_infix_direction_to_str(
                    infix_direction_node.value,
                ));
            }
            so_far.push(' ');
            if let Some(infix_precedence_node) = maybe_infix_precedence {
                use std::fmt::Write as _;
                let _ = write!(so_far, "{}", infix_precedence_node.value);
            }
            so_far.push_str(" (");
            if let Some(operator_node) = maybe_operator {
                so_far.push_str(operator_node.value);
            }
            so_far.push_str(") = ");
            if let Some(implementation_function_name) = maybe_implementation_function_name {
                so_far.push_str(&implementation_function_name.value);
            }
        }
        GrenSyntaxDeclaration::Port {
            name: maybe_name,
            colon_key_symbol_range: _,
            type_: maybe_type,
        } => {
            gren_syntax_port_declaration_into(
                so_far,
                comments,
                |qualified| qualified.qualification,
                declaration_node.range,
                maybe_name.as_ref().map(gren_syntax_node_unbox),
                maybe_type.as_ref().map(gren_syntax_node_as_ref),
            );
        }
        GrenSyntaxDeclaration::TypeAlias {
            alias_keyword_range: _,
            name: maybe_name,
            parameters,
            equals_key_symbol_range: _,
            type_: maybe_type,
        } => {
            gren_syntax_type_alias_declaration_into(
                so_far,
                comments,
                |qualified| qualified.qualification,
                declaration_node.range,
                maybe_name.as_ref().map(gren_syntax_node_unbox),
                parameters,
                maybe_type.as_ref().map(gren_syntax_node_as_ref),
            );
        }
        GrenSyntaxDeclaration::Variable {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        } => {
            gren_syntax_variable_declaration_into(
                so_far,
                0,
                comments,
                gren_syntax_node_unbox(start_name_node),
                maybe_signature.as_ref(),
                parameters,
                *maybe_equals_key_symbol_range,
                maybe_result.as_ref().map(gren_syntax_node_as_ref),
            );
        }
    }
}
fn gren_syntax_port_declaration_into<'a>(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    maybe_type: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
) {
    let mut previous_syntax_end: lsp_types::Position = declaration_range.start;
    so_far.push_str("port ");
    if let Some(name_node) = maybe_name {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            5,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: declaration_range.start,
                    end: name_node.range.start,
                },
            ),
        );
        so_far.push_str(name_node.value);
        previous_syntax_end = name_node.range.end;
    }
    if let Some(type_node) = maybe_type {
        so_far.push_str(" :");
        let comments_before_type = gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: previous_syntax_end,
                end: type_node.range.start,
            },
        );
        let annotation_line_span: LineSpan = if comments_before_type.is_empty() {
            gren_syntax_range_line_span(type_node.range, comments)
        } else {
            LineSpan::Multiple
        };
        space_or_linebreak_indented_into(so_far, annotation_line_span, 4);
        gren_syntax_comments_then_linebreak_indented_into(so_far, 4, comments_before_type);
        gren_syntax_type_not_parenthesized_into(
            so_far,
            4,
            assign_qualification,
            comments,
            type_node,
        );
    }
}
fn gren_syntax_type_alias_declaration_into<'a>(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    parameters: &[GrenSyntaxNode<Box<str>>],
    maybe_type: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
) {
    let mut previous_syntax_end: lsp_types::Position = declaration_range.start;
    so_far.push_str("type alias ");
    if let Some(name_node) = maybe_name {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            11,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: declaration_range.start,
                    end: name_node.range.start,
                },
            ),
        );
        so_far.push_str(name_node.value);
        previous_syntax_end = name_node.range.end;
    }
    let comments_before_and_between_parameters = match parameters.last() {
        None => &[],
        Some(last_parameter) => gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: previous_syntax_end,
                end: last_parameter.range.end,
            },
        ),
    };
    for parameter_node in parameters {
        if comments_before_and_between_parameters.is_empty() {
            so_far.push(' ');
        } else {
            linebreak_indented_into(so_far, 12);
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                12,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: previous_syntax_end,
                        end: parameter_node.range.start,
                    },
                ),
            );
        }
        so_far.push_str(&parameter_node.value);
        previous_syntax_end = parameter_node.range.end;
    }
    if let Some(type_node) = maybe_type {
        space_or_linebreak_indented_into(
            so_far,
            if comments_before_and_between_parameters.is_empty() {
                LineSpan::Single
            } else {
                LineSpan::Multiple
            },
            4,
        );
        so_far.push('=');
        linebreak_indented_into(so_far, 4);
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            4,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: type_node.range.start,
                },
            ),
        );
        gren_syntax_type_not_parenthesized_into(
            so_far,
            4,
            assign_qualification,
            comments,
            type_node,
        );
    }
}
fn gren_syntax_choice_type_declaration_into<'a>(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    declaration_range: lsp_types::Range,
    maybe_name: Option<GrenSyntaxNode<&str>>,
    parameters: &[GrenSyntaxNode<Box<str>>],
    maybe_variant0_name: Option<GrenSyntaxNode<&str>>,
    variant0_maybe_value: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
    variant1_up: &'a [GrenSyntaxChoiceTypeDeclarationTailingVariant],
) {
    let mut previous_syntax_end: lsp_types::Position = declaration_range.start;
    so_far.push_str("type ");
    if let Some(name_node) = maybe_name {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            5,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: declaration_range.start,
                    end: name_node.range.start,
                },
            ),
        );
        so_far.push_str(name_node.value);
        previous_syntax_end = name_node.range.end;
    }
    let comments_before_and_between_parameters = match parameters.last() {
        None => &[],
        Some(last_parameter) => gren_syntax_comments_in_range(
            comments,
            lsp_types::Range {
                start: previous_syntax_end,
                end: last_parameter.range.end,
            },
        ),
    };
    for parameter_node in parameters {
        if comments_before_and_between_parameters.is_empty() {
            so_far.push(' ');
        } else {
            linebreak_indented_into(so_far, 8);
            gren_syntax_comments_then_linebreak_indented_into(
                so_far,
                8,
                gren_syntax_comments_in_range(
                    comments,
                    lsp_types::Range {
                        start: previous_syntax_end,
                        end: parameter_node.range.start,
                    },
                ),
            );
        }
        so_far.push_str(&parameter_node.value);
        previous_syntax_end = parameter_node.range.end;
    }
    linebreak_indented_into(so_far, 4);
    so_far.push_str("= ");
    previous_syntax_end = gren_syntax_choice_type_declaration_variant_into(
        so_far,
        comments,
        assign_qualification,
        previous_syntax_end,
        maybe_variant0_name,
        variant0_maybe_value,
    );
    for variant in variant1_up {
        linebreak_indented_into(so_far, 4);
        so_far.push_str("| ");
        previous_syntax_end = gren_syntax_choice_type_declaration_variant_into(
            so_far,
            comments,
            assign_qualification,
            previous_syntax_end,
            variant
                .name
                .as_ref()
                .map(|variant_name_node| gren_syntax_node_unbox(variant_name_node)),
            variant.value.as_ref().map(gren_syntax_node_as_ref),
        );
    }
}
fn gren_syntax_choice_type_declaration_variant_into<'a>(
    so_far: &mut String,
    comments: &[GrenSyntaxNode<GrenSyntaxComment>],
    assign_qualification: impl Fn(GrenQualified<'a>) -> &'a str + Copy,
    mut previous_syntax_end: lsp_types::Position,
    maybe_variant_name: Option<GrenSyntaxNode<&str>>,
    variant_maybe_value: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
) -> lsp_types::Position {
    if let Some(variant_name_node) = maybe_variant_name {
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            6,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: variant_name_node.range.start,
                },
            ),
        );
        so_far.push_str(variant_name_node.value);
        previous_syntax_end = variant_name_node.range.end;
    }
    let Some(variant_last_value_node) = variant_maybe_value else {
        return previous_syntax_end;
    };
    let line_span: LineSpan = gren_syntax_range_line_span(
        lsp_types::Range {
            start: previous_syntax_end,
            end: variant_last_value_node.range.end,
        },
        comments,
    );
    if let Some(value_node) = variant_maybe_value {
        space_or_linebreak_indented_into(so_far, line_span, 8);
        gren_syntax_comments_then_linebreak_indented_into(
            so_far,
            8,
            gren_syntax_comments_in_range(
                comments,
                lsp_types::Range {
                    start: previous_syntax_end,
                    end: value_node.range.start,
                },
            ),
        );
        gren_syntax_type_parenthesized_if_space_separated_into(
            so_far,
            8,
            assign_qualification,
            comments,
            value_node.range,
            gren_syntax_type_to_unparenthesized(value_node),
        );
        previous_syntax_end = value_node.range.end;
    }
    previous_syntax_end
}

// //
#[derive(Clone, Debug)]
enum GrenSyntaxSymbol<'a> {
    ModuleName(&'a str),
    ImportAlias {
        module_origin: &'a str,
        alias_name: &'a str,
    },
    ModuleHeaderExpose {
        name: &'a str,
        all_exposes: &'a [GrenSyntaxNode<GrenSyntaxExpose>],
    },
    ModuleDocumentationAtDocsMember {
        name: &'a str,
        module_documentation: &'a [GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
    },
    // includes variant
    ModuleMemberDeclarationName {
        name: &'a str,
        documentation: Option<&'a str>,
        declaration: GrenSyntaxNode<&'a GrenSyntaxDeclaration>,
    },
    ImportExpose {
        origin_module: &'a str,
        name: &'a str,
        all_exposes: &'a [GrenSyntaxNode<GrenSyntaxExpose>],
    },
    LetDeclarationName {
        name: &'a str,
        start_name_range: lsp_types::Range,
        signature_type: Option<GrenSyntaxNode<&'a GrenSyntaxType>>,
        scope_expression: GrenSyntaxNode<&'a GrenSyntaxExpression>,
    },
    VariableOrVariantOrOperator {
        qualification: &'a str,
        name: &'a str,
        // consider wrapping in Option
        local_bindings: GrenLocalBindings<'a>,
    },
    Type {
        qualification: &'a str,
        name: &'a str,
    },
    TypeVariable {
        scope_declaration: &'a GrenSyntaxDeclaration,
        name: &'a str,
    },
}
type GrenLocalBindings<'a> = Vec<(
    GrenSyntaxNode<&'a GrenSyntaxExpression>,
    Vec<GrenLocalBinding<'a>>,
)>;
fn find_local_binding_scope_expression<'a>(
    local_bindings: &GrenLocalBindings<'a>,
    to_find: &str,
) -> Option<(
    LocalBindingOrigin<'a>,
    GrenSyntaxNode<&'a GrenSyntaxExpression>,
)> {
    local_bindings
        .iter()
        .find_map(|(scope_expression, local_bindings)| {
            local_bindings.iter().find_map(|local_binding| {
                if local_binding.name == to_find {
                    Some((local_binding.origin, *scope_expression))
                } else {
                    None
                }
            })
        })
}

fn gren_syntax_module_find_symbol_at_position<'a>(
    gren_syntax_module: &'a GrenSyntaxModule,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    gren_syntax_module
        .header
        .as_ref()
        .and_then(|module_header| {
            gren_syntax_module_header_find_reference_at_position(module_header, position)
        })
        .or_else(|| {
            gren_syntax_module
                .documentation
                .as_ref()
                .and_then(|module_documentation_node| {
                    gren_syntax_module_documentation_find_symbol_at_position(
                        gren_syntax_node_as_ref_map(module_documentation_node, Vec::as_slice),
                        position,
                    )
                })
        })
        .or_else(|| {
            gren_syntax_module.imports.iter().find_map(|import_node| {
                gren_syntax_import_find_reference_at_position(
                    gren_syntax_node_as_ref(import_node),
                    position,
                )
            })
        })
        .or_else(|| {
            gren_syntax_module
                .declarations
                .iter()
                .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
                .find_map(|documented_declaration| {
                    let declaration_node = documented_declaration.declaration.as_ref()?;
                    gren_syntax_declaration_find_reference_at_position(
                        gren_syntax_node_as_ref(declaration_node),
                        documented_declaration
                            .documentation
                            .as_ref()
                            .map(|node| node.value.as_ref()),
                        position,
                    )
                })
        })
}
fn gren_syntax_module_documentation_find_symbol_at_position<'a>(
    gren_syntax_module_documentation: GrenSyntaxNode<
        &'a [GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
    >,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    gren_syntax_module_documentation
        .value
        .iter()
        .find_map(|documentation_element_node| {
            if !lsp_range_includes_position(documentation_element_node.range, position) {
                return None;
            }
            match &documentation_element_node.value {
                GrenSyntaxModuleDocumentationElement::Markdown(_) => None,
                GrenSyntaxModuleDocumentationElement::AtDocs(member_names) => {
                    member_names.iter().find_map(|member_name_node| {
                        if lsp_range_includes_position(member_name_node.range, position) {
                            Some(GrenSyntaxNode {
                                range: member_name_node.range,
                                value: GrenSyntaxSymbol::ModuleDocumentationAtDocsMember {
                                    name: member_name_node
                                        .value
                                        .trim_start_matches('(')
                                        .trim_end_matches(')'),
                                    module_documentation: gren_syntax_module_documentation.value,
                                },
                            })
                        } else {
                            None
                        }
                    })
                }
            }
        })
}
fn gren_syntax_module_header_find_reference_at_position<'a>(
    gren_syntax_module_header: &'a GrenSyntaxModuleHeader,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if let Some(module_name_node) = &gren_syntax_module_header.module_name
        && lsp_range_includes_position(module_name_node.range, position)
    {
        Some(GrenSyntaxNode {
            value: GrenSyntaxSymbol::ModuleName(&module_name_node.value),
            range: module_name_node.range,
        })
    } else {
        let exposing_node: &GrenSyntaxNode<GrenSyntaxExposing> =
            gren_syntax_module_header.exposing.as_ref()?;
        gren_syntax_module_header_exposing_from_module_find_reference_at_position(
            gren_syntax_node_as_ref(exposing_node),
            position,
        )
    }
}

fn gren_syntax_import_find_reference_at_position<'a>(
    gren_syntax_import_node: GrenSyntaxNode<&'a GrenSyntaxImport>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if !lsp_range_includes_position(gren_syntax_import_node.range, position) {
        return None;
    }
    let module_name_node = gren_syntax_import_node.value.module_name.as_ref()?;
    if lsp_range_includes_position(module_name_node.range, position) {
        Some(GrenSyntaxNode {
            value: GrenSyntaxSymbol::ModuleName(&module_name_node.value),
            range: module_name_node.range,
        })
    } else if let Some(import_alias_name_node) = &gren_syntax_import_node.value.alias_name
        && lsp_range_includes_position(import_alias_name_node.range, position)
    {
        Some(GrenSyntaxNode {
            value: GrenSyntaxSymbol::ImportAlias {
                module_origin: &module_name_node.value,
                alias_name: &import_alias_name_node.value,
            },
            range: module_name_node.range,
        })
    } else {
        gren_syntax_import_node
            .value
            .exposing
            .as_ref()
            .and_then(|exposing| {
                gren_syntax_import_exposing_from_module_find_reference_at_position(
                    &module_name_node.value,
                    gren_syntax_node_as_ref(exposing),
                    position,
                )
            })
    }
}

fn gren_syntax_module_header_exposing_from_module_find_reference_at_position<'a>(
    gren_syntax_exposing_node: GrenSyntaxNode<&'a GrenSyntaxExposing>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if !lsp_range_includes_position(gren_syntax_exposing_node.range, position) {
        return None;
    }
    match gren_syntax_exposing_node.value {
        GrenSyntaxExposing::All(_) => None,
        GrenSyntaxExposing::Explicit(exposes) => exposes.iter().find_map(|expose_node| {
            if lsp_range_includes_position(expose_node.range, position) {
                let expose_name: &str = match &expose_node.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name,
                        open_range: _,
                    } => Some(name.value.as_ref()),
                    GrenSyntaxExpose::Operator(maybe_symbol) => {
                        maybe_symbol.as_ref().map(|symbol_node| symbol_node.value)
                    }
                    GrenSyntaxExpose::Type(name) => Some(name.as_ref()),
                    GrenSyntaxExpose::Variable(name) => Some(name.as_ref()),
                }?;
                Some(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::ModuleHeaderExpose {
                        name: expose_name,
                        all_exposes: exposes,
                    },
                    range: expose_node.range,
                })
            } else {
                None
            }
        }),
    }
}
fn gren_syntax_import_exposing_from_module_find_reference_at_position<'a>(
    import_origin_module: &'a str,
    gren_syntax_exposing_node: GrenSyntaxNode<&'a GrenSyntaxExposing>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if !lsp_range_includes_position(gren_syntax_exposing_node.range, position) {
        return None;
    }
    match gren_syntax_exposing_node.value {
        GrenSyntaxExposing::All(_) => None,
        GrenSyntaxExposing::Explicit(exposes) => exposes.iter().find_map(|expose_node| {
            if lsp_range_includes_position(expose_node.range, position) {
                let expose_name: &str = match &expose_node.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name,
                        open_range: _,
                    } => Some(name.value.as_ref()),
                    GrenSyntaxExpose::Operator(maybe_symbol) => {
                        maybe_symbol.as_ref().map(|symbol_node| symbol_node.value)
                    }
                    GrenSyntaxExpose::Type(name) => Some(name.as_ref()),
                    GrenSyntaxExpose::Variable(name) => Some(name.as_ref()),
                }?;
                Some(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::ImportExpose {
                        origin_module: import_origin_module,
                        name: expose_name,
                        all_exposes: exposes,
                    },
                    range: expose_node.range,
                })
            } else {
                None
            }
        }),
    }
}

fn gren_syntax_declaration_find_reference_at_position<'a>(
    gren_syntax_declaration_node: GrenSyntaxNode<&'a GrenSyntaxDeclaration>,
    maybe_documentation: Option<&'a str>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if !lsp_range_includes_position(gren_syntax_declaration_node.range, position) {
        None
    } else {
        match gren_syntax_declaration_node.value {
            GrenSyntaxDeclaration::ChoiceType {
                name: maybe_name,
                parameters,
                equals_key_symbol_range: _,
                variant0_name: maybe_variant0_name,
                variant0_value: variant0_maybe_value,
                variant1_up,
            } => {
                if let Some(name_node) = maybe_name
                    && lsp_range_includes_position(name_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: &name_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: name_node.range,
                    })
                } else if let Some(variant0_name_node) = maybe_variant0_name
                    && lsp_range_includes_position(variant0_name_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: &variant0_name_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: variant0_name_node.range,
                    })
                } else {
                    parameters
                        .iter()
                        .find_map(|parameter_node| {
                            if lsp_range_includes_position(parameter_node.range, position) {
                                Some(GrenSyntaxNode {
                                    value: GrenSyntaxSymbol::TypeVariable {
                                        scope_declaration: gren_syntax_declaration_node.value,
                                        name: &parameter_node.value,
                                    },
                                    range: parameter_node.range,
                                })
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            variant0_maybe_value.as_ref().and_then(|variant_value| {
                                gren_syntax_type_find_reference_at_position(
                                    gren_syntax_declaration_node.value,
                                    gren_syntax_node_as_ref(variant_value),
                                    position,
                                )
                            })
                        })
                        .or_else(|| {
                            variant1_up.iter().find_map(|variant| {
                                if let Some(variant_name_node) = &variant.name
                                    && lsp_range_includes_position(
                                        variant_name_node.range,
                                        position,
                                    )
                                {
                                    Some(GrenSyntaxNode {
                                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                                            name: &variant_name_node.value,
                                            declaration: gren_syntax_declaration_node,
                                            documentation: maybe_documentation,
                                        },
                                        range: variant_name_node.range,
                                    })
                                } else {
                                    variant.value.as_ref().and_then(|variant_value| {
                                        gren_syntax_type_find_reference_at_position(
                                            gren_syntax_declaration_node.value,
                                            gren_syntax_node_as_ref(variant_value),
                                            position,
                                        )
                                    })
                                }
                            })
                        })
                }
            }
            GrenSyntaxDeclaration::Operator {
                direction: _,
                precedence: _,
                equals_key_symbol_range: _,
                operator: maybe_operator,
                function: maybe_function,
            } => {
                if let Some(operator_node) = maybe_operator
                    && lsp_range_includes_position(operator_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: operator_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: operator_node.range,
                    })
                } else if let Some(function_node) = maybe_function
                    && lsp_range_includes_position(function_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                            qualification: "",
                            name: &function_node.value,
                            local_bindings: vec![],
                        },
                        range: function_node.range,
                    })
                } else {
                    None
                }
            }
            GrenSyntaxDeclaration::Port {
                name: maybe_name,
                colon_key_symbol_range: _,
                type_: maybe_type,
            } => {
                if let Some(name_node) = maybe_name
                    && lsp_range_includes_position(name_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: &name_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: name_node.range,
                    })
                } else {
                    maybe_type.as_ref().and_then(|type_node| {
                        gren_syntax_type_find_reference_at_position(
                            gren_syntax_declaration_node.value,
                            gren_syntax_node_as_ref(type_node),
                            position,
                        )
                    })
                }
            }
            GrenSyntaxDeclaration::TypeAlias {
                alias_keyword_range: _,
                name: maybe_name,
                parameters,
                equals_key_symbol_range: _,
                type_: maybe_type,
            } => {
                if let Some(name_node) = maybe_name
                    && lsp_range_includes_position(name_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: &name_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: name_node.range,
                    })
                } else {
                    parameters
                        .iter()
                        .find_map(|parameter_node| {
                            if lsp_range_includes_position(parameter_node.range, position) {
                                Some(GrenSyntaxNode {
                                    value: GrenSyntaxSymbol::TypeVariable {
                                        scope_declaration: gren_syntax_declaration_node.value,
                                        name: &parameter_node.value,
                                    },
                                    range: parameter_node.range,
                                })
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            maybe_type.as_ref().and_then(|type_node| {
                                gren_syntax_type_find_reference_at_position(
                                    gren_syntax_declaration_node.value,
                                    gren_syntax_node_as_ref(type_node),
                                    position,
                                )
                            })
                        })
                }
            }
            GrenSyntaxDeclaration::Variable {
                start_name: start_name_node,
                signature: maybe_signature,
                parameters,
                equals_key_symbol_range: _,
                result: maybe_result,
            } => {
                if lsp_range_includes_position(start_name_node.range, position) {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                            name: &start_name_node.value,
                            declaration: gren_syntax_declaration_node,
                            documentation: maybe_documentation,
                        },
                        range: start_name_node.range,
                    })
                } else {
                    maybe_signature
                        .as_ref()
                        .and_then(|signature: &GrenSyntaxVariableDeclarationSignature| {
                            if let Some(implementation_name_range) =
                                signature.implementation_name_range
                                && lsp_range_includes_position(implementation_name_range, position)
                            {
                                Some(GrenSyntaxNode {
                                    value: GrenSyntaxSymbol::ModuleMemberDeclarationName {
                                        name: &start_name_node.value,
                                        declaration: gren_syntax_declaration_node,
                                        documentation: maybe_documentation,
                                    },
                                    range: start_name_node.range,
                                })
                            } else {
                                signature.type_.as_ref().and_then(|signature_type_node| {
                                    gren_syntax_type_find_reference_at_position(
                                        gren_syntax_declaration_node.value,
                                        gren_syntax_node_as_ref(signature_type_node),
                                        position,
                                    )
                                })
                            }
                        })
                        .or_else(|| {
                            let mut parameter_introduced_bindings: Vec<GrenLocalBinding> =
                                Vec::new();
                            for parameter_node in parameters {
                                gren_syntax_pattern_bindings_into(
                                    &mut parameter_introduced_bindings,
                                    gren_syntax_node_as_ref(parameter_node),
                                );
                            }
                            maybe_result.as_ref().and_then(|result_node| {
                                gren_syntax_expression_find_reference_at_position(
                                    vec![(
                                        gren_syntax_node_as_ref(result_node),
                                        parameter_introduced_bindings,
                                    )],
                                    gren_syntax_declaration_node.value,
                                    gren_syntax_node_as_ref(result_node),
                                    position,
                                )
                                .break_value()
                            })
                        })
                        .or_else(|| {
                            parameters.iter().find_map(|parameter| {
                                gren_syntax_pattern_find_reference_at_position(
                                    gren_syntax_node_as_ref(parameter),
                                    position,
                                )
                            })
                        })
                }
            }
        }
    }
}

fn gren_syntax_pattern_find_reference_at_position<'a>(
    gren_syntax_pattern_node: GrenSyntaxNode<&'a GrenSyntaxPattern>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    match gren_syntax_pattern_node.value {
        GrenSyntaxPattern::As {
            pattern,
            as_keyword_range: _,
            variable: _,
        } => gren_syntax_pattern_find_reference_at_position(
            gren_syntax_node_unbox(pattern),
            position,
        ),
        GrenSyntaxPattern::Char(_) => None,
        GrenSyntaxPattern::Ignored(_) => None,
        GrenSyntaxPattern::Int { .. } => None,
        GrenSyntaxPattern::Parenthesized(maybe_in_parens) => {
            maybe_in_parens.as_ref().and_then(|in_parens| {
                gren_syntax_pattern_find_reference_at_position(
                    gren_syntax_node_unbox(in_parens),
                    position,
                )
            })
        }
        GrenSyntaxPattern::Record(_) => None,
        GrenSyntaxPattern::String { .. } => None,
        GrenSyntaxPattern::Variable(_) => None,
        GrenSyntaxPattern::Variant {
            reference,
            value: maybe_value,
        } => {
            if lsp_range_includes_position(reference.range, position) {
                Some(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                        qualification: &reference.value.qualification,
                        name: &reference.value.name,
                        local_bindings: vec![],
                    },
                    range: reference.range,
                })
            } else {
                maybe_value.as_ref().and_then(|value| {
                    gren_syntax_pattern_find_reference_at_position(
                        gren_syntax_node_unbox(value),
                        position,
                    )
                })
            }
        }
    }
}

fn gren_syntax_type_find_reference_at_position<'a>(
    scope_declaration: &'a GrenSyntaxDeclaration,
    gren_syntax_type_node: GrenSyntaxNode<&'a GrenSyntaxType>,
    position: lsp_types::Position,
) -> Option<GrenSyntaxNode<GrenSyntaxSymbol<'a>>> {
    if !lsp_range_includes_position(gren_syntax_type_node.range, position) {
        None
    } else {
        match gren_syntax_type_node.value {
            GrenSyntaxType::Construct {
                reference,
                arguments,
            } => {
                if lsp_range_includes_position(reference.range, position) {
                    Some(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::Type {
                            qualification: &reference.value.qualification,
                            name: &reference.value.name,
                        },
                        range: reference.range,
                    })
                } else {
                    arguments.iter().find_map(|argument| {
                        gren_syntax_type_find_reference_at_position(
                            scope_declaration,
                            gren_syntax_node_as_ref(argument),
                            position,
                        )
                    })
                }
            }
            GrenSyntaxType::Function {
                input,
                arrow_key_symbol_range: _,
                output: maybe_output,
            } => gren_syntax_type_find_reference_at_position(
                scope_declaration,
                gren_syntax_node_unbox(input),
                position,
            )
            .or_else(|| {
                maybe_output.as_ref().and_then(|output_node| {
                    gren_syntax_type_find_reference_at_position(
                        scope_declaration,
                        gren_syntax_node_unbox(output_node),
                        position,
                    )
                })
            }),
            GrenSyntaxType::Parenthesized(maybe_in_parens) => {
                maybe_in_parens.as_ref().and_then(|in_parens| {
                    gren_syntax_type_find_reference_at_position(
                        scope_declaration,
                        gren_syntax_node_unbox(in_parens),
                        position,
                    )
                })
            }
            GrenSyntaxType::Record(fields) => fields.iter().find_map(|field| {
                field.value.as_ref().and_then(|field_value_node| {
                    gren_syntax_type_find_reference_at_position(
                        scope_declaration,
                        gren_syntax_node_as_ref(field_value_node),
                        position,
                    )
                })
            }),
            GrenSyntaxType::RecordExtension {
                record_variable: maybe_record_type_variable,
                bar_key_symbol_range: _,
                fields,
            } => {
                if let Some(record_type_variable_node) = maybe_record_type_variable
                    && lsp_range_includes_position(record_type_variable_node.range, position)
                {
                    Some(GrenSyntaxNode {
                        range: record_type_variable_node.range,
                        value: GrenSyntaxSymbol::TypeVariable {
                            scope_declaration: scope_declaration,
                            name: &record_type_variable_node.value,
                        },
                    })
                } else {
                    fields.iter().find_map(|field| {
                        field.value.as_ref().and_then(|field_value_node| {
                            gren_syntax_type_find_reference_at_position(
                                scope_declaration,
                                gren_syntax_node_as_ref(field_value_node),
                                position,
                            )
                        })
                    })
                }
            }
            GrenSyntaxType::Variable(type_variable_value) => Some(GrenSyntaxNode {
                range: gren_syntax_type_node.range,
                value: GrenSyntaxSymbol::TypeVariable {
                    scope_declaration: scope_declaration,
                    name: type_variable_value,
                },
            }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum LocalBindingOrigin<'a> {
    // consider separately tracking parameter names (let or otherwise), including their origin declaration name and annotation type when available
    PatternVariable(lsp_types::Range),
    PatternRecordField(lsp_types::Range),
    LetDeclaredVariable {
        signature: Option<&'a GrenSyntaxVariableDeclarationSignature>,
        start_name_range: lsp_types::Range,
    },
}
#[derive(Clone, Copy, Debug)]
struct GrenLocalBinding<'a> {
    name: &'a str,
    origin: LocalBindingOrigin<'a>,
}

fn on_some_break<A>(maybe: Option<A>) -> std::ops::ControlFlow<A, ()> {
    match maybe {
        None => std::ops::ControlFlow::Continue(()),
        Some(value) => std::ops::ControlFlow::Break(value),
    }
}

fn gren_syntax_expression_find_reference_at_position<'a>(
    mut local_bindings: GrenLocalBindings<'a>,
    scope_declaration: &'a GrenSyntaxDeclaration,
    gren_syntax_expression_node: GrenSyntaxNode<&'a GrenSyntaxExpression>,
    position: lsp_types::Position,
) -> std::ops::ControlFlow<GrenSyntaxNode<GrenSyntaxSymbol<'a>>, GrenLocalBindings<'a>> {
    if !lsp_range_includes_position(gren_syntax_expression_node.range, position) {
        return std::ops::ControlFlow::Continue(local_bindings);
    }
    match gren_syntax_expression_node.value {
        GrenSyntaxExpression::Call {
            called,
            argument0,
            argument1_up,
        } => {
            local_bindings = gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(called),
                position,
            )?;
            local_bindings = gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(argument0),
                position,
            )?;
            argument1_up
                .iter()
                .try_fold(local_bindings, |local_bindings, argument| {
                    gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_as_ref(argument),
                        position,
                    )
                })
        }
        GrenSyntaxExpression::CaseOf {
            matched: maybe_matched,
            of_keyword_range: _,
            cases,
        } => {
            if let Some(matched_node) = maybe_matched {
                local_bindings = gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(matched_node),
                    position,
                )?;
            }
            cases
                .iter()
                .try_fold(local_bindings, |mut local_bindings, case| {
                    if let Some(found_symbol) = gren_syntax_pattern_find_reference_at_position(
                        gren_syntax_node_as_ref(&case.pattern),
                        position,
                    ) {
                        return std::ops::ControlFlow::Break(found_symbol);
                    }
                    if let Some(case_result_node) = &case.result
                    && // we need to check that the position is actually in that case before committing to mutating local bindings
                    lsp_range_includes_position(case_result_node.range, position)
                    {
                        let mut introduced_bindings: Vec<GrenLocalBinding> = Vec::new();
                        gren_syntax_pattern_bindings_into(
                            &mut introduced_bindings,
                            gren_syntax_node_as_ref(&case.pattern),
                        );
                        local_bindings.push((
                            gren_syntax_node_as_ref(case_result_node),
                            introduced_bindings,
                        ));
                        gren_syntax_expression_find_reference_at_position(
                            local_bindings,
                            scope_declaration,
                            gren_syntax_node_as_ref(case_result_node),
                            position,
                        )
                    } else {
                        std::ops::ControlFlow::Continue(local_bindings)
                    }
                })
        }
        GrenSyntaxExpression::Char(_) => std::ops::ControlFlow::Continue(local_bindings),
        GrenSyntaxExpression::Float(_) => std::ops::ControlFlow::Continue(local_bindings),
        GrenSyntaxExpression::IfThenElse {
            condition: maybe_condition,
            then_keyword_range: _,
            on_true: maybe_on_true,
            else_keyword_range: _,
            on_false: maybe_on_false,
        } => {
            if let Some(condition_node) = maybe_condition {
                local_bindings = gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(condition_node),
                    position,
                )?;
            }
            if let Some(on_true_node) = maybe_on_true {
                local_bindings = gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(on_true_node),
                    position,
                )?;
            }
            match maybe_on_false {
                Some(on_false_node) => gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(on_false_node),
                    position,
                ),
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
        GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
            left,
            operator,
            right: maybe_right,
        } => {
            if lsp_range_includes_position(operator.range, position) {
                return std::ops::ControlFlow::Break(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                        qualification: "",
                        name: operator.value,
                        local_bindings: local_bindings,
                    },
                    range: operator.range,
                });
            }
            local_bindings = gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(left),
                position,
            )?;
            match maybe_right {
                Some(right_node) => gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(right_node),
                    position,
                ),
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
        GrenSyntaxExpression::Integer { .. } => std::ops::ControlFlow::Continue(local_bindings),
        GrenSyntaxExpression::Lambda {
            arrow_key_symbol_range: _,
            parameters,
            result: maybe_result,
        } => {
            if let Some(found_symbol) = parameters.iter().find_map(|parameter| {
                gren_syntax_pattern_find_reference_at_position(
                    gren_syntax_node_as_ref(parameter),
                    position,
                )
            }) {
                return std::ops::ControlFlow::Break(found_symbol);
            }
            match maybe_result {
                Some(result_node) => {
                    let mut introduced_bindings: Vec<GrenLocalBinding> = Vec::new();
                    for parameter_node in parameters {
                        gren_syntax_pattern_bindings_into(
                            &mut introduced_bindings,
                            gren_syntax_node_as_ref(parameter_node),
                        );
                    }
                    local_bindings.push((gren_syntax_node_unbox(result_node), introduced_bindings));
                    gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_unbox(result_node),
                        position,
                    )
                }
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
        GrenSyntaxExpression::LetIn {
            declarations,
            in_keyword_range: _,
            result: maybe_result,
        } => {
            let mut introduced_bindings: Vec<GrenLocalBinding> = Vec::new();
            for let_declaration_node in declarations {
                gren_syntax_let_declaration_introduced_bindings_into(
                    &mut introduced_bindings,
                    &let_declaration_node.value,
                );
            }
            local_bindings.push((gren_syntax_expression_node, introduced_bindings));
            local_bindings =
                declarations
                    .iter()
                    .try_fold(local_bindings, |local_bindings, declaration| {
                        gren_syntax_let_declaration_find_reference_at_position(
                            local_bindings,
                            scope_declaration,
                            gren_syntax_expression_node,
                            gren_syntax_node_as_ref(declaration),
                            position,
                        )
                    })?;
            match maybe_result {
                Some(result_node) => gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_unbox(result_node),
                    position,
                ),
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
        GrenSyntaxExpression::Array(elements) => {
            elements
                .iter()
                .try_fold(local_bindings, |local_bindings, element| {
                    gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_as_ref(element),
                        position,
                    )
                })
        }
        GrenSyntaxExpression::Negation(maybe_in_negation) => match maybe_in_negation {
            Some(in_negation_node) => gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(in_negation_node),
                position,
            ),
            None => std::ops::ControlFlow::Continue(local_bindings),
        },
        GrenSyntaxExpression::OperatorFunction(operator_node) => {
            std::ops::ControlFlow::Break(GrenSyntaxNode {
                value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                    qualification: "",
                    name: operator_node.value,
                    local_bindings: local_bindings,
                },
                range: gren_syntax_expression_node.range,
            })
        }
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => match maybe_in_parens {
            Some(in_parens) => gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(in_parens),
                position,
            ),
            None => std::ops::ControlFlow::Continue(local_bindings),
        },
        GrenSyntaxExpression::Record(fields) => {
            fields
                .iter()
                .try_fold(local_bindings, |local_bindings, field| match &field.value {
                    Some(field_value_node) => gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_as_ref(field_value_node),
                        position,
                    ),
                    None => std::ops::ControlFlow::Continue(local_bindings),
                })
        }
        GrenSyntaxExpression::RecordAccess { record, field: _ } => {
            gren_syntax_expression_find_reference_at_position(
                local_bindings,
                scope_declaration,
                gren_syntax_node_unbox(record),
                position,
            )
        }
        GrenSyntaxExpression::RecordAccessFunction(_) => {
            std::ops::ControlFlow::Continue(local_bindings)
        }
        GrenSyntaxExpression::RecordUpdate {
            record_variable: maybe_record_variable,
            bar_key_symbol_range: _,
            fields,
        } => {
            if let Some(record_variable_node) = maybe_record_variable
                && lsp_range_includes_position(record_variable_node.range, position)
            {
                return std::ops::ControlFlow::Break(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                        qualification: "",
                        name: &record_variable_node.value,
                        local_bindings: local_bindings,
                    },
                    range: record_variable_node.range,
                });
            }
            fields
                .iter()
                .try_fold(local_bindings, |local_bindings, field| match &field.value {
                    Some(field_value_node) => gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_as_ref(field_value_node),
                        position,
                    ),
                    None => std::ops::ControlFlow::Continue(local_bindings),
                })
        }
        GrenSyntaxExpression::Reference {
            qualification,
            name,
        } => std::ops::ControlFlow::Break(GrenSyntaxNode {
            value: GrenSyntaxSymbol::VariableOrVariantOrOperator {
                qualification: qualification,
                name: name,
                local_bindings: local_bindings,
            },
            range: gren_syntax_expression_node.range,
        }),
        GrenSyntaxExpression::String { .. } => std::ops::ControlFlow::Continue(local_bindings),
    }
}

fn gren_syntax_let_declaration_find_reference_at_position<'a>(
    mut local_bindings: GrenLocalBindings<'a>,
    scope_declaration: &'a GrenSyntaxDeclaration,
    scope_expression: GrenSyntaxNode<&'a GrenSyntaxExpression>,
    gren_syntax_let_declaration_node: GrenSyntaxNode<&'a GrenSyntaxLetDeclaration>,
    position: lsp_types::Position,
) -> std::ops::ControlFlow<GrenSyntaxNode<GrenSyntaxSymbol<'a>>, GrenLocalBindings<'a>> {
    if !lsp_range_includes_position(gren_syntax_let_declaration_node.range, position) {
        return std::ops::ControlFlow::Continue(local_bindings);
    }
    match gren_syntax_let_declaration_node.value {
        GrenSyntaxLetDeclaration::Destructuring {
            pattern,
            equals_key_symbol_range: _,
            expression: maybe_expression,
        } => {
            on_some_break(gren_syntax_pattern_find_reference_at_position(
                gren_syntax_node_as_ref(pattern),
                position,
            ))?;
            match maybe_expression {
                Some(expression_node) => gren_syntax_expression_find_reference_at_position(
                    local_bindings,
                    scope_declaration,
                    gren_syntax_node_as_ref(expression_node),
                    position,
                ),
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
        GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: _,
            result: maybe_result,
        } => {
            if lsp_range_includes_position(start_name.range, position) {
                return std::ops::ControlFlow::Break(GrenSyntaxNode {
                    value: GrenSyntaxSymbol::LetDeclarationName {
                        name: &start_name.value,
                        start_name_range: start_name.range,
                        signature_type: maybe_signature
                            .as_ref()
                            .and_then(|signature| signature.type_.as_ref())
                            .map(gren_syntax_node_as_ref),
                        scope_expression: scope_expression,
                    },
                    range: start_name.range,
                });
            }
            on_some_break(parameters.iter().find_map(|parameter| {
                gren_syntax_pattern_find_reference_at_position(
                    gren_syntax_node_as_ref(parameter),
                    position,
                )
            }))?;
            if let Some(signature) = maybe_signature {
                if let Some(implementation_name_range) = signature.implementation_name_range
                    && lsp_range_includes_position(implementation_name_range, position)
                {
                    return std::ops::ControlFlow::Break(GrenSyntaxNode {
                        value: GrenSyntaxSymbol::LetDeclarationName {
                            name: &start_name.value,
                            start_name_range: start_name.range,
                            signature_type: signature.type_.as_ref().map(gren_syntax_node_as_ref),
                            scope_expression: scope_expression,
                        },
                        range: implementation_name_range,
                    });
                }
                if let Some(signature_type_node) = &signature.type_ {
                    on_some_break(gren_syntax_type_find_reference_at_position(
                        scope_declaration,
                        gren_syntax_node_as_ref(signature_type_node),
                        position,
                    ))?;
                }
            }
            match maybe_result {
                Some(result_node) => {
                    let mut introduced_bindings: Vec<GrenLocalBinding> = Vec::new();
                    for parameter_node in parameters {
                        gren_syntax_pattern_bindings_into(
                            &mut introduced_bindings,
                            gren_syntax_node_as_ref(parameter_node),
                        );
                    }
                    local_bindings
                        .push((gren_syntax_node_as_ref(result_node), introduced_bindings));
                    gren_syntax_expression_find_reference_at_position(
                        local_bindings,
                        scope_declaration,
                        gren_syntax_node_as_ref(result_node),
                        position,
                    )
                }
                None => std::ops::ControlFlow::Continue(local_bindings),
            }
        }
    }
}

// //
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GrenSymbolToReference<'a> {
    ModuleName(&'a str),
    ImportAlias {
        module_origin: &'a str,
        alias_name: &'a str,
    },
    TypeVariable(&'a str),
    // type is tracked separately from VariableOrVariant because e.g. variants and
    // type names are allowed to overlap
    Type {
        module_origin: &'a str,
        name: &'a str,
        including_declaration_name: bool,
    },
    VariableOrVariant {
        module_origin: &'a str,
        name: &'a str,
        including_declaration_name: bool,
    },
    LocalBinding {
        name: &'a str,
        including_let_declaration_name: bool,
    },
}

fn gren_syntax_module_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    state: &State,
    project_state: &ProjectState,
    gren_syntax_module: &GrenSyntaxModule,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    let maybe_self_module_name: Option<&GrenSyntaxNode<Box<str>>> = gren_syntax_module
        .header
        .as_ref()
        .and_then(|header| header.module_name.as_ref());
    if let Some(self_module_name_node) = maybe_self_module_name
        && let GrenSymbolToReference::ModuleName(module_name_to_collect_uses_of) =
            symbol_to_collect_uses_of
        && module_name_to_collect_uses_of == self_module_name_node.value.as_ref()
    {
        uses_so_far.push(self_module_name_node.range);
        // a module cannot reference itself within its declarations, imports etc
        return;
    }
    let symbol_to_collect_can_occur_here: bool = match symbol_to_collect_uses_of {
        GrenSymbolToReference::ModuleName(module_origin_to_collect_uses_of)
        | GrenSymbolToReference::Type {
            module_origin: module_origin_to_collect_uses_of,
            name: _,
            including_declaration_name: _,
        }
        | GrenSymbolToReference::VariableOrVariant {
            module_origin: module_origin_to_collect_uses_of,
            name: _,
            including_declaration_name: _,
        } => {
            Some(module_origin_to_collect_uses_of)
                == maybe_self_module_name
                    .as_ref()
                    .map(|node| node.value.as_ref())
                || gren_syntax_module.imports.iter().any(|import| {
                    import
                        .value
                        .module_name
                        .as_ref()
                        .map(|node| node.value.as_ref())
                        == Some(module_origin_to_collect_uses_of)
                })
        }
        GrenSymbolToReference::ImportAlias { .. } => false,
        GrenSymbolToReference::TypeVariable(_) => false,
        GrenSymbolToReference::LocalBinding { .. } => false,
    };
    if !symbol_to_collect_can_occur_here {
        // if not imported, that module name can never appear, so we can skip a bunch of
        // traversing! (unless implicitly imported, but those modules are never renamed!)
        return;
    }
    let self_module_name: &str = maybe_self_module_name
        .map(|node| node.value.as_ref())
        .unwrap_or("");
    if let Some(module_header) = &gren_syntax_module.header
        && let Some(exposing) = &module_header.exposing
    {
        gren_syntax_exposing_uses_of_reference_into(
            uses_so_far,
            self_module_name,
            &exposing.value,
            symbol_to_collect_uses_of,
        );
    }
    if let Some(module_documentation_node) = &gren_syntax_module.documentation {
        gren_syntax_module_documentation_uses_of_reference_into(
            uses_so_far,
            self_module_name,
            &module_documentation_node.value,
            symbol_to_collect_uses_of,
        );
    }
    for import in gren_syntax_module.imports.iter() {
        gren_syntax_import_uses_of_reference_into(
            uses_so_far,
            &import.value,
            symbol_to_collect_uses_of,
        );
    }
    let module_origin_lookup: ModuleOriginLookup =
        gren_syntax_module_create_origin_lookup(state, project_state, gren_syntax_module);
    for documented_declaration in gren_syntax_module
        .declarations
        .iter()
        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
    {
        if let Some(declaration_node) = &documented_declaration.declaration {
            gren_syntax_declaration_uses_of_reference_into(
                uses_so_far,
                self_module_name,
                &module_origin_lookup,
                &declaration_node.value,
                symbol_to_collect_uses_of,
            );
        }
    }
}
fn gren_syntax_module_documentation_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    origin_module: &str,
    gren_syntax_module_documentation: &[GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    let Some(member_to_collect_uses_of) = (match symbol_to_collect_uses_of {
        GrenSymbolToReference::ModuleName(_) => None,
        GrenSymbolToReference::ImportAlias { .. } => None,
        GrenSymbolToReference::TypeVariable(_) => None,
        GrenSymbolToReference::LocalBinding { .. } => None,
        GrenSymbolToReference::Type {
            module_origin: symbol_module_origin,
            name,
            including_declaration_name: _,
        }
        | GrenSymbolToReference::VariableOrVariant {
            module_origin: symbol_module_origin,
            name,
            including_declaration_name: _,
        } => {
            if symbol_module_origin == origin_module {
                Some(name)
            } else {
                None
            }
        }
    }) else {
        return;
    };
    for gren_syntax_module_documentation_element_node in gren_syntax_module_documentation {
        match &gren_syntax_module_documentation_element_node.value {
            GrenSyntaxModuleDocumentationElement::Markdown(_) => {}
            GrenSyntaxModuleDocumentationElement::AtDocs(at_docs_member_names) => {
                for at_docs_member_name_node in at_docs_member_names {
                    if at_docs_member_name_node.value.as_ref() == member_to_collect_uses_of {
                        uses_so_far.push(at_docs_member_name_node.range);
                    }
                }
            }
        }
    }
}
fn gren_syntax_import_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    gren_syntax_import: &GrenSyntaxImport,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    let Some(import_module_name_node) = &gren_syntax_import.module_name else {
        return;
    };
    if let GrenSymbolToReference::ModuleName(module_name_to_collect_uses_of) =
        symbol_to_collect_uses_of
    {
        if module_name_to_collect_uses_of == import_module_name_node.value.as_ref() {
            uses_so_far.push(import_module_name_node.range);
        }
    } else if let GrenSymbolToReference::ImportAlias {
        module_origin: alias_to_collect_uses_of_origin,
        alias_name: alias_to_collect_uses_of_name,
    } = symbol_to_collect_uses_of
    {
        if alias_to_collect_uses_of_origin == import_module_name_node.value.as_ref()
            && let Some(import_alias_name_node) = &gren_syntax_import.alias_name
            && alias_to_collect_uses_of_name == import_alias_name_node.value.as_ref()
        {
            uses_so_far.push(import_alias_name_node.range);
        }
    } else if let Some(exposing) = &gren_syntax_import.exposing {
        gren_syntax_exposing_uses_of_reference_into(
            uses_so_far,
            &import_module_name_node.value,
            &exposing.value,
            symbol_to_collect_uses_of,
        );
    }
}

fn gren_syntax_exposing_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    origin_module: &str,
    gren_syntax_exposing: &GrenSyntaxExposing,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_exposing {
        GrenSyntaxExposing::All(_) => {}
        GrenSyntaxExposing::Explicit(exposes) => {
            for expose in exposes {
                match &expose.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name,
                        open_range: _,
                    } => {
                        if let GrenSymbolToReference::Type {
                            name: symbol_name,
                            module_origin: symbol_module_origin,
                            including_declaration_name: _,
                        } = symbol_to_collect_uses_of
                            && symbol_name == name.value.as_ref()
                            && symbol_module_origin == origin_module
                        {
                            uses_so_far.push(name.range);
                        }
                    }
                    GrenSyntaxExpose::Operator(_) => {}
                    GrenSyntaxExpose::Type(name) => {
                        if let GrenSymbolToReference::Type {
                            name: symbol_name,
                            module_origin: symbol_module_origin,
                            including_declaration_name: _,
                        } = symbol_to_collect_uses_of
                            && symbol_name == name.as_ref()
                            && symbol_module_origin == origin_module
                        {
                            uses_so_far.push(expose.range);
                        }
                    }
                    GrenSyntaxExpose::Variable(name) => {
                        if let GrenSymbolToReference::VariableOrVariant {
                            name: symbol_name,
                            module_origin: symbol_module_origin,
                            including_declaration_name: _,
                        } = symbol_to_collect_uses_of
                            && symbol_name == name.as_ref()
                            && symbol_module_origin == origin_module
                        {
                            uses_so_far.push(expose.range);
                        }
                    }
                }
            }
        }
    }
}

fn gren_syntax_declaration_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    origin_module: &str,
    module_origin_lookup: &ModuleOriginLookup,
    gren_syntax_declaration: &GrenSyntaxDeclaration,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_declaration {
        GrenSyntaxDeclaration::ChoiceType {
            name: maybe_name,
            parameters,
            equals_key_symbol_range: _,
            variant0_name: maybe_variant0_name,
            variant0_value: variant0_maybe_value,
            variant1_up,
        } => {
            if let Some(name_node) = maybe_name
                && symbol_to_collect_uses_of
                    == (GrenSymbolToReference::Type {
                        module_origin: origin_module,
                        name: &name_node.value,
                        including_declaration_name: true,
                    })
            {
                uses_so_far.push(name_node.range);
            }
            'parameter_traversal: for parameter_node in parameters {
                if symbol_to_collect_uses_of
                    == GrenSymbolToReference::TypeVariable(&parameter_node.value)
                {
                    uses_so_far.push(parameter_node.range);
                    break 'parameter_traversal;
                }
            }
            if let Some(variant0_name_node) = maybe_variant0_name
                && symbol_to_collect_uses_of
                    == (GrenSymbolToReference::VariableOrVariant {
                        name: &variant0_name_node.value,
                        module_origin: origin_module,
                        including_declaration_name: true,
                    })
            {
                uses_so_far.push(variant0_name_node.range);
                return;
            }
            if let Some(variant0_value) = variant0_maybe_value {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(variant0_value),
                    symbol_to_collect_uses_of,
                );
            }
            for variant in variant1_up {
                if let Some(variant_name_node) = &variant.name
                    && (GrenSymbolToReference::VariableOrVariant {
                        name: &variant_name_node.value,
                        module_origin: origin_module,
                        including_declaration_name: true,
                    }) == symbol_to_collect_uses_of
                {
                    uses_so_far.push(variant_name_node.range);
                    return;
                }
                if let Some(variant0_value) = &variant.value {
                    gren_syntax_type_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        gren_syntax_node_as_ref(variant0_value),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxDeclaration::Operator { .. } => {}
        GrenSyntaxDeclaration::Port {
            name: maybe_name,
            colon_key_symbol_range: _,
            type_: maybe_type,
        } => {
            if let Some(name_node) = maybe_name
                && symbol_to_collect_uses_of
                    == (GrenSymbolToReference::VariableOrVariant {
                        name: &name_node.value,
                        module_origin: origin_module,
                        including_declaration_name: true,
                    })
            {
                uses_so_far.push(name_node.range);
            }
            if let Some(type_node) = maybe_type {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(type_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxDeclaration::TypeAlias {
            alias_keyword_range: _,
            name: maybe_name,
            parameters,
            equals_key_symbol_range: _,
            type_: maybe_type,
        } => {
            if let Some(name_node) = maybe_name
                && symbol_to_collect_uses_of
                    == (GrenSymbolToReference::Type {
                        name: &name_node.value,
                        module_origin: origin_module,
                        including_declaration_name: true,
                    })
            {
                uses_so_far.push(name_node.range);
            }
            'parameter_traversal: for parameter_node in parameters {
                if symbol_to_collect_uses_of
                    == GrenSymbolToReference::TypeVariable(&parameter_node.value)
                {
                    uses_so_far.push(parameter_node.range);
                    break 'parameter_traversal;
                }
            }
            if let Some(type_node) = maybe_type {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(type_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxDeclaration::Variable {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: _,
            result: maybe_result,
        } => {
            if symbol_to_collect_uses_of
                == (GrenSymbolToReference::VariableOrVariant {
                    name: &start_name_node.value,
                    module_origin: origin_module,
                    including_declaration_name: true,
                })
            {
                uses_so_far.push(start_name_node.range);
            }
            if let Some(signature) = maybe_signature {
                if let Some(implementation_name_range) = signature.implementation_name_range
                    && symbol_to_collect_uses_of
                        == (GrenSymbolToReference::VariableOrVariant {
                            name: &start_name_node.value,
                            module_origin: origin_module,
                            including_declaration_name: true,
                        })
                {
                    uses_so_far.push(implementation_name_range);
                }
                if let Some(signature_type_node) = &signature.type_ {
                    gren_syntax_type_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        gren_syntax_node_as_ref(signature_type_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
            for parameter in parameters {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(parameter),
                    symbol_to_collect_uses_of,
                );
            }
            let mut parameter_bindings: Vec<GrenLocalBinding> = Vec::new();
            for parameter_node in parameters {
                gren_syntax_pattern_bindings_into(
                    &mut parameter_bindings,
                    gren_syntax_node_as_ref(parameter_node),
                );
            }
            if let Some(result_node) = maybe_result {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    &parameter_bindings,
                    gren_syntax_node_as_ref(result_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
    }
}

fn gren_syntax_type_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    module_origin_lookup: &ModuleOriginLookup,
    gren_syntax_type_node: GrenSyntaxNode<&GrenSyntaxType>,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_type_node.value {
        GrenSyntaxType::Construct {
            reference,
            arguments,
        } => {
            let module_origin: &str = look_up_origin_module(
                module_origin_lookup,
                GrenQualified {
                    qualification: &reference.value.qualification,
                    name: &reference.value.name,
                },
            );
            if let GrenSymbolToReference::Type {
                name: symbol_name,
                module_origin: symbol_module_origin,
                including_declaration_name: _,
            } = symbol_to_collect_uses_of
                && symbol_module_origin == module_origin
                && symbol_name == reference.value.name.as_ref()
            {
                uses_so_far.push(lsp_types::Range {
                    start: lsp_position_add_characters(
                        reference.range.end,
                        -(reference.value.name.len() as i32),
                    ),
                    end: reference.range.end,
                });
            }
            if (symbol_to_collect_uses_of
                == (GrenSymbolToReference::ImportAlias {
                    module_origin: module_origin,
                    alias_name: &reference.value.qualification,
                }))
                || (symbol_to_collect_uses_of == GrenSymbolToReference::ModuleName(module_origin))
                    && (reference.value.qualification.as_ref() == module_origin)
            {
                uses_so_far.push(lsp_types::Range {
                    start: reference.range.start,
                    end: lsp_position_add_characters(
                        reference.range.start,
                        reference.value.qualification.len() as i32,
                    ),
                });
            }
            for argument in arguments {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(argument),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxType::Function {
            input,
            arrow_key_symbol_range: _,
            output: maybe_output,
        } => {
            gren_syntax_type_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                gren_syntax_node_unbox(input),
                symbol_to_collect_uses_of,
            );
            if let Some(output_node) = maybe_output {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_unbox(output_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxType::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_unbox(in_parens),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxType::Record(fields) => {
            for field in fields {
                if let Some(field_value_node) = &field.value {
                    gren_syntax_type_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        gren_syntax_node_as_ref(field_value_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxType::RecordExtension {
            record_variable: maybe_record_variable,
            bar_key_symbol_range: _,
            fields,
        } => {
            if let Some(record_variable_node) = maybe_record_variable
                && symbol_to_collect_uses_of
                    == GrenSymbolToReference::TypeVariable(&record_variable_node.value)
            {
                uses_so_far.push(record_variable_node.range);
            }
            for field in fields {
                if let Some(field_value_node) = &field.value {
                    gren_syntax_type_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        gren_syntax_node_as_ref(field_value_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxType::Variable(variable) => {
            if symbol_to_collect_uses_of == GrenSymbolToReference::TypeVariable(variable) {
                uses_so_far.push(gren_syntax_type_node.range);
            }
        }
    }
}

fn gren_syntax_expression_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    module_origin_lookup: &ModuleOriginLookup,
    local_bindings: &[GrenLocalBinding],
    gren_syntax_expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_expression_node.value {
        GrenSyntaxExpression::Call {
            called,
            argument0,
            argument1_up,
        } => {
            gren_syntax_expression_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                local_bindings,
                gren_syntax_node_unbox(called),
                symbol_to_collect_uses_of,
            );
            gren_syntax_expression_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                local_bindings,
                gren_syntax_node_unbox(argument0),
                symbol_to_collect_uses_of,
            );
            for argument_node in argument1_up {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_as_ref(argument_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::CaseOf {
            matched: maybe_matched,
            of_keyword_range: _,
            cases,
        } => {
            if let Some(matched_node) = maybe_matched {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(matched_node),
                    symbol_to_collect_uses_of,
                );
            }
            for case in cases {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(&case.pattern),
                    symbol_to_collect_uses_of,
                );
                if let Some(case_result_node) = &case.result {
                    let mut local_bindings_including_from_case_pattern: Vec<GrenLocalBinding> =
                        local_bindings.to_vec();
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings_including_from_case_pattern,
                        gren_syntax_node_as_ref(&case.pattern),
                    );
                    gren_syntax_expression_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        &local_bindings_including_from_case_pattern,
                        gren_syntax_node_as_ref(case_result_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxExpression::Char(_) => {}
        GrenSyntaxExpression::Float(_) => {}
        GrenSyntaxExpression::IfThenElse {
            condition: maybe_condition,
            then_keyword_range: _,
            on_true: maybe_on_true,
            else_keyword_range: _,
            on_false: maybe_on_false,
        } => {
            if let Some(condition_node) = maybe_condition {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(condition_node),
                    symbol_to_collect_uses_of,
                );
            }
            if let Some(on_true_node) = maybe_on_true {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(on_true_node),
                    symbol_to_collect_uses_of,
                );
            }
            if let Some(on_false_node) = maybe_on_false {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(on_false_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
            left,
            operator: _,
            right: maybe_right,
        } => {
            gren_syntax_expression_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                local_bindings,
                gren_syntax_node_unbox(left),
                symbol_to_collect_uses_of,
            );
            if let Some(right_node) = maybe_right {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(right_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::Integer { .. } => {}
        GrenSyntaxExpression::Lambda {
            parameters,
            arrow_key_symbol_range: _,
            result: maybe_result,
        } => {
            for parameter_node in parameters {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(parameter_node),
                    symbol_to_collect_uses_of,
                );
            }
            if let Some(result_node) = maybe_result {
                let mut local_bindings_including_from_lambda_parameters = local_bindings.to_vec();
                for parameter_node in parameters {
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings_including_from_lambda_parameters,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                }
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    &local_bindings_including_from_lambda_parameters,
                    gren_syntax_node_unbox(result_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::LetIn {
            declarations,
            in_keyword_range: _,
            result: maybe_result,
        } => {
            let mut local_bindings_including_let_declaration_introduced: Vec<GrenLocalBinding> =
                local_bindings.to_vec();
            for let_declaration_node in declarations {
                gren_syntax_let_declaration_introduced_bindings_into(
                    &mut local_bindings_including_let_declaration_introduced,
                    &let_declaration_node.value,
                );
            }
            for let_declaration_node in declarations {
                gren_syntax_let_declaration_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    &local_bindings_including_let_declaration_introduced,
                    &let_declaration_node.value,
                    symbol_to_collect_uses_of,
                );
            }
            if let Some(result) = maybe_result {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    &local_bindings_including_let_declaration_introduced,
                    gren_syntax_node_unbox(result),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::Array(elements) => {
            for element_node in elements {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_as_ref(element_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::Negation(maybe_in_negation) => {
            if let Some(in_negation_node) = maybe_in_negation {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(in_negation_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::OperatorFunction(_) => {}
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_unbox(in_parens),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxExpression::Record(fields) => {
            for field in fields {
                if let Some(field_value_node) = &field.value {
                    gren_syntax_expression_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        local_bindings,
                        gren_syntax_node_as_ref(field_value_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxExpression::RecordAccess { record, field: _ } => {
            gren_syntax_expression_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                local_bindings,
                gren_syntax_node_unbox(record),
                symbol_to_collect_uses_of,
            );
        }
        GrenSyntaxExpression::RecordAccessFunction(_) => {}
        GrenSyntaxExpression::RecordUpdate {
            record_variable: maybe_record_variable,
            bar_key_symbol_range: _,
            fields,
        } => {
            if let Some(record_variable_node) = maybe_record_variable {
                if let GrenSymbolToReference::LocalBinding {
                    name: symbol_name,
                    including_let_declaration_name: _,
                } = symbol_to_collect_uses_of
                    && symbol_name == record_variable_node.value.as_ref()
                {
                    if local_bindings.iter().any(|local_binding| {
                        local_binding.name == record_variable_node.value.as_ref()
                    }) {
                        uses_so_far.push(record_variable_node.range);
                    }
                } else if let GrenSymbolToReference::VariableOrVariant {
                    module_origin: symbol_module_origin,
                    name: symbol_name,
                    including_declaration_name: _,
                } = symbol_to_collect_uses_of
                    && symbol_module_origin
                        == look_up_origin_module(
                            module_origin_lookup,
                            GrenQualified {
                                qualification: "",
                                name: &record_variable_node.value,
                            },
                        )
                    && symbol_name == record_variable_node.value.as_ref()
                {
                    uses_so_far.push(record_variable_node.range);
                }
            }
            for field in fields {
                if let Some(field_value_node) = &field.value {
                    gren_syntax_expression_uses_of_reference_into(
                        uses_so_far,
                        module_origin_lookup,
                        local_bindings,
                        gren_syntax_node_as_ref(field_value_node),
                        symbol_to_collect_uses_of,
                    );
                }
            }
        }
        GrenSyntaxExpression::Reference {
            qualification,
            name,
        } => {
            if let GrenSymbolToReference::LocalBinding {
                name: symbol_name,
                including_let_declaration_name: _,
            } = symbol_to_collect_uses_of
                && symbol_name == name.as_ref()
            {
                if qualification.is_empty()
                    && local_bindings
                        .iter()
                        .any(|local_binding| local_binding.name == name.as_ref())
                {
                    uses_so_far.push(gren_syntax_expression_node.range);
                }
            } else {
                let module_origin: &str = look_up_origin_module(
                    module_origin_lookup,
                    GrenQualified {
                        qualification: qualification,
                        name: name,
                    },
                );
                if let GrenSymbolToReference::VariableOrVariant {
                    module_origin: symbol_module_origin,
                    name: symbol_name,
                    including_declaration_name: _,
                } = symbol_to_collect_uses_of
                    && symbol_module_origin == module_origin
                    && symbol_name == name.as_ref()
                {
                    uses_so_far.push(lsp_types::Range {
                        start: lsp_position_add_characters(
                            gren_syntax_expression_node.range.end,
                            -(name.len() as i32),
                        ),
                        end: gren_syntax_expression_node.range.end,
                    });
                } else if (symbol_to_collect_uses_of
                    == (GrenSymbolToReference::ImportAlias {
                        module_origin: module_origin,
                        alias_name: qualification,
                    }))
                    || ((symbol_to_collect_uses_of
                        == GrenSymbolToReference::ModuleName(module_origin))
                        && (qualification.as_ref() == module_origin))
                {
                    uses_so_far.push(lsp_types::Range {
                        start: gren_syntax_expression_node.range.start,
                        end: lsp_position_add_characters(
                            gren_syntax_expression_node.range.start,
                            qualification.len() as i32,
                        ),
                    });
                }
            }
        }
        GrenSyntaxExpression::String { .. } => {}
    }
}

fn gren_syntax_let_declaration_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    module_origin_lookup: &ModuleOriginLookup,
    local_bindings: &[GrenLocalBinding],
    gren_syntax_let_declaration: &GrenSyntaxLetDeclaration,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_let_declaration {
        GrenSyntaxLetDeclaration::Destructuring {
            pattern,
            equals_key_symbol_range: _,
            expression: maybe_expression,
        } => {
            gren_syntax_pattern_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                gren_syntax_node_as_ref(pattern),
                symbol_to_collect_uses_of,
            );
            if let Some(expression_node) = maybe_expression {
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    local_bindings,
                    gren_syntax_node_as_ref(expression_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: _,
            result: maybe_result,
        } => {
            if symbol_to_collect_uses_of
                == (GrenSymbolToReference::LocalBinding {
                    name: &start_name_node.value,
                    including_let_declaration_name: true,
                })
            {
                uses_so_far.push(start_name_node.range);
                if let Some(signature) = maybe_signature
                    && let Some(implementation_name_range) = signature.implementation_name_range
                {
                    uses_so_far.push(implementation_name_range);
                }
                return;
            }
            if let Some(signature) = maybe_signature
                && let Some(signature_type_node) = &signature.type_
            {
                gren_syntax_type_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(signature_type_node),
                    symbol_to_collect_uses_of,
                );
            }
            for parameter in parameters {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_as_ref(parameter),
                    symbol_to_collect_uses_of,
                );
            }
            if let Some(result_node) = maybe_result {
                let mut local_bindings_including_from_let_function_parameters: Vec<
                    GrenLocalBinding,
                > = local_bindings.to_vec();
                for parameter_node in parameters {
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings_including_from_let_function_parameters,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                }
                gren_syntax_expression_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    &local_bindings_including_from_let_function_parameters,
                    gren_syntax_node_as_ref(result_node),
                    symbol_to_collect_uses_of,
                );
            }
        }
    }
}

fn gren_syntax_pattern_uses_of_reference_into(
    uses_so_far: &mut Vec<lsp_types::Range>,
    module_origin_lookup: &ModuleOriginLookup,
    gren_syntax_pattern_node: GrenSyntaxNode<&GrenSyntaxPattern>,
    symbol_to_collect_uses_of: GrenSymbolToReference,
) {
    match gren_syntax_pattern_node.value {
        GrenSyntaxPattern::As {
            pattern: alias_pattern,
            as_keyword_range: _,
            variable: _,
        } => {
            gren_syntax_pattern_uses_of_reference_into(
                uses_so_far,
                module_origin_lookup,
                gren_syntax_node_unbox(alias_pattern),
                symbol_to_collect_uses_of,
            );
        }
        GrenSyntaxPattern::Char(_) => {}
        GrenSyntaxPattern::Ignored(_) => {}
        GrenSyntaxPattern::Int { .. } => {}
        GrenSyntaxPattern::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_unbox(in_parens),
                    symbol_to_collect_uses_of,
                );
            }
        }
        GrenSyntaxPattern::Record(_) => {}
        GrenSyntaxPattern::String { .. } => {}
        GrenSyntaxPattern::Variable(_) => {}
        GrenSyntaxPattern::Variant {
            reference,
            value: maybe_value,
        } => {
            let module_origin: &str = look_up_origin_module(
                module_origin_lookup,
                GrenQualified {
                    qualification: &reference.value.qualification,
                    name: &reference.value.name,
                },
            );
            if let GrenSymbolToReference::VariableOrVariant {
                module_origin: symbol_module_origin,
                name: symbol_name,
                including_declaration_name: _,
            } = symbol_to_collect_uses_of
                && symbol_module_origin == module_origin
                && symbol_name == reference.value.name.as_ref()
            {
                uses_so_far.push(lsp_types::Range {
                    start: lsp_position_add_characters(
                        reference.range.end,
                        -(reference.value.name.len() as i32),
                    ),
                    end: reference.range.end,
                });
            }
            if (symbol_to_collect_uses_of
                == (GrenSymbolToReference::ImportAlias {
                    module_origin: module_origin,
                    alias_name: &reference.value.qualification,
                }))
                || ((symbol_to_collect_uses_of == GrenSymbolToReference::ModuleName(module_origin))
                    && (reference.value.qualification.as_ref() == module_origin))
            {
                uses_so_far.push(lsp_types::Range {
                    start: reference.range.start,
                    end: lsp_position_add_characters(
                        reference.range.start,
                        reference.value.qualification.len() as i32,
                    ),
                });
            }
            if let Some(value) = maybe_value {
                gren_syntax_pattern_uses_of_reference_into(
                    uses_so_far,
                    module_origin_lookup,
                    gren_syntax_node_unbox(value),
                    symbol_to_collect_uses_of,
                );
            }
        }
    }
}

fn gren_syntax_let_declaration_introduced_bindings_into<'a>(
    bindings_so_far: &mut Vec<GrenLocalBinding<'a>>,
    gren_syntax_let_declaration: &'a GrenSyntaxLetDeclaration,
) {
    match gren_syntax_let_declaration {
        GrenSyntaxLetDeclaration::Destructuring { pattern, .. } => {
            gren_syntax_pattern_bindings_into(bindings_so_far, gren_syntax_node_as_ref(pattern));
        }
        GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name: start_name_node,
            signature,
            ..
        } => {
            bindings_so_far.push(GrenLocalBinding {
                name: &start_name_node.value,
                origin: LocalBindingOrigin::LetDeclaredVariable {
                    signature: signature.as_ref(),
                    start_name_range: start_name_node.range,
                },
            });
        }
    }
}

fn gren_syntax_pattern_bindings_into<'a>(
    bindings_so_far: &mut Vec<GrenLocalBinding<'a>>,
    gren_syntax_pattern_node: GrenSyntaxNode<&'a GrenSyntaxPattern>,
) {
    match gren_syntax_pattern_node.value {
        GrenSyntaxPattern::As {
            pattern: aliased_pattern_node,
            as_keyword_range: _,
            variable: maybe_variable,
        } => {
            gren_syntax_pattern_bindings_into(
                bindings_so_far,
                gren_syntax_node_unbox(aliased_pattern_node),
            );
            if let Some(variable_node) = maybe_variable {
                bindings_so_far.push(GrenLocalBinding {
                    origin: LocalBindingOrigin::PatternVariable(variable_node.range),
                    name: &variable_node.value,
                });
            }
        }
        GrenSyntaxPattern::Char(_) => {}
        GrenSyntaxPattern::Ignored(_) => {}
        GrenSyntaxPattern::Int { .. } => {}
        GrenSyntaxPattern::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_pattern_bindings_into(
                    bindings_so_far,
                    gren_syntax_node_unbox(in_parens),
                );
            }
        }
        GrenSyntaxPattern::Record(field_names) => {
            for field in field_names {
                gren_syntax_pattern_field_bindings_into(bindings_so_far, field);
            }
        }
        GrenSyntaxPattern::String { .. } => {}
        GrenSyntaxPattern::Variable(variable) => {
            bindings_so_far.push(GrenLocalBinding {
                origin: LocalBindingOrigin::PatternVariable(gren_syntax_pattern_node.range),
                name: variable,
            });
        }
        GrenSyntaxPattern::Variant {
            reference: _,
            value: maybe_value,
        } => {
            if let Some(value_node) = maybe_value {
                gren_syntax_pattern_bindings_into(
                    bindings_so_far,
                    gren_syntax_node_unbox(value_node),
                );
            }
        }
    }
}
fn gren_syntax_pattern_field_bindings_into<'a>(
    bindings_so_far: &mut Vec<GrenLocalBinding<'a>>,
    gren_syntax_pattern_field: &'a GrenSyntaxPatternField,
) {
    match &gren_syntax_pattern_field.value {
        None => {
            if gren_syntax_pattern_field.equals_key_symbol_range.is_none() {
                bindings_so_far.push(GrenLocalBinding {
                    name: &gren_syntax_pattern_field.name.value,
                    origin: LocalBindingOrigin::PatternRecordField(
                        gren_syntax_pattern_field.name.range,
                    ),
                });
            }
        }
        Some(field_value) => {
            gren_syntax_pattern_bindings_into(
                bindings_so_far,
                gren_syntax_node_as_ref(field_value),
            );
        }
    }
}

enum GrenSyntaxHighlightKind {
    Type,
    TypeVariable,
    Variant,
    Field,
    ModuleNameOrAlias,
    Variable,
    Comment,
    String,
    Number,
    DeclaredVariable,
    Operator,
    KeySymbol,
}

fn gren_syntax_highlight_module_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_module: &GrenSyntaxModule,
) {
    if let Some(module_header) = &gren_syntax_module.header {
        gren_syntax_highlight_module_header_into(highlighted_so_far, module_header);
    }
    if let Some(documentation_node) = &gren_syntax_module.documentation {
        gren_syntax_highlight_module_documentation_into(
            highlighted_so_far,
            gren_syntax_node_as_ref_map(documentation_node, Vec::as_slice),
        );
    }
    for import_node in gren_syntax_module.imports.iter() {
        gren_syntax_highlight_import_into(highlighted_so_far, gren_syntax_node_as_ref(import_node));
    }
    for documented_declaration in gren_syntax_module
        .declarations
        .iter()
        .filter_map(|declaration_or_err| declaration_or_err.as_ref().ok())
    {
        if let Some(documentation_node) = &documented_declaration.documentation {
            highlighted_so_far.extend(
                gren_syntax_highlight_multi_line(gren_syntax_node_unbox(documentation_node), 3, 2)
                    .map(|range| GrenSyntaxNode {
                        range: range,
                        value: GrenSyntaxHighlightKind::Comment,
                    }),
            );
        }
        if let Some(declaration_node) = &documented_declaration.declaration {
            gren_syntax_highlight_declaration_into(
                highlighted_so_far,
                gren_syntax_node_as_ref(declaration_node),
            );
        }
    }
    // Inserting many comments in the middle can get expensive (having so many comments to make it matter will be rare).
    // A possible solution (when comment count exceeds other syntax by some factor) is just pushing all comments an sorting the whole thing at once.
    // Feels like overkill, though so I'll hold on on this until issues are opened :)
    for comment_node in gren_syntax_module.comments.iter() {
        gren_syntax_highlight_and_place_comment_into(
            highlighted_so_far,
            gren_syntax_node_as_ref(comment_node),
        );
    }
}
fn gren_syntax_highlight_module_documentation_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_module_documentation_node: GrenSyntaxNode<
        &[GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>],
    >,
) {
    highlighted_so_far.push(GrenSyntaxNode {
        range: lsp_types::Range {
            start: gren_syntax_module_documentation_node.range.start,
            end: lsp_position_add_characters(gren_syntax_module_documentation_node.range.start, 3),
        },
        value: GrenSyntaxHighlightKind::Comment,
    });
    for gren_syntax_module_documentation_element_node in gren_syntax_module_documentation_node.value
    {
        match &gren_syntax_module_documentation_element_node.value {
            GrenSyntaxModuleDocumentationElement::Markdown(markdown) => {
                highlighted_so_far.extend(
                    gren_syntax_highlight_multi_line(
                        GrenSyntaxNode {
                            range: gren_syntax_module_documentation_element_node.range,
                            value: markdown,
                        },
                        0,
                        0,
                    )
                    .map(|range| GrenSyntaxNode {
                        range: range,
                        value: GrenSyntaxHighlightKind::Comment,
                    }),
                );
            }
            GrenSyntaxModuleDocumentationElement::AtDocs(member_names) => {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: gren_syntax_module_documentation_element_node.range.start,
                        end: lsp_position_add_characters(
                            gren_syntax_module_documentation_element_node.range.start,
                            5,
                        ),
                    },
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                for member_name_node in member_names {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: member_name_node.range,
                        value: if member_name_node.value.starts_with(char::is_uppercase) {
                            GrenSyntaxHighlightKind::Type
                        } else if member_name_node.value.starts_with(char::is_lowercase) {
                            GrenSyntaxHighlightKind::DeclaredVariable
                        } else {
                            GrenSyntaxHighlightKind::Operator
                        },
                    });
                }
            }
        }
    }
    highlighted_so_far.push(GrenSyntaxNode {
        range: lsp_types::Range {
            start: gren_syntax_module_documentation_node.range.end,
            end: lsp_position_add_characters(gren_syntax_module_documentation_node.range.end, 2),
        },
        value: GrenSyntaxHighlightKind::Comment,
    });
}
fn gren_syntax_highlight_module_header_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_module_header: &GrenSyntaxModuleHeader,
) {
    match &gren_syntax_module_header.specific {
        GrenSyntaxModuleHeaderSpecific::Pure {
            module_keyword_range,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: *module_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(module_name_range) = &gren_syntax_module_header.module_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: module_name_range.range,
                    value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
                });
            }
            if let Some(exposing_keyword_range) = gren_syntax_module_header.exposing_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: exposing_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(exposing_node) = &gren_syntax_module_header.exposing {
                gren_syntax_highlight_exposing_into(highlighted_so_far, &exposing_node.value);
            }
        }
        GrenSyntaxModuleHeaderSpecific::Effect {
            effect_keyword_range,
            module_keyword_range,
            where_keyword_range,
            command: maybe_command,
            subscription: maybe_subscription,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: *effect_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            highlighted_so_far.push(GrenSyntaxNode {
                range: *module_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(module_name_node) = &gren_syntax_module_header.module_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: module_name_node.range,
                    value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
                });
            }
            highlighted_so_far.push(GrenSyntaxNode {
                range: *where_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(command_node) = maybe_command {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: command_node.key_range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                highlighted_so_far.push(GrenSyntaxNode {
                    range: command_node.equals_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                highlighted_so_far.push(GrenSyntaxNode {
                    range: command_node.value_type_name.range,
                    value: GrenSyntaxHighlightKind::DeclaredVariable,
                });
            }
            if let Some(subscription_node) = maybe_subscription {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: subscription_node.key_range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                highlighted_so_far.push(GrenSyntaxNode {
                    range: subscription_node.equals_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                highlighted_so_far.push(GrenSyntaxNode {
                    range: subscription_node.value_type_name.range,
                    value: GrenSyntaxHighlightKind::DeclaredVariable,
                });
            }
        }
        GrenSyntaxModuleHeaderSpecific::Port {
            module_keyword_range,
            port_keyword_range,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: *port_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            highlighted_so_far.push(GrenSyntaxNode {
                range: *module_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(module_name_node) = &gren_syntax_module_header.module_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: module_name_node.range,
                    value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
                });
            }
            if let Some(exposing_keyword_range) = gren_syntax_module_header.exposing_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: exposing_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(exposing) = &gren_syntax_module_header.exposing {
                gren_syntax_highlight_exposing_into(highlighted_so_far, &exposing.value);
            }
        }
    }
}

fn gren_syntax_highlight_and_place_comment_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_comment_node: GrenSyntaxNode<&GrenSyntaxComment>,
) {
    let insert_index: usize = highlighted_so_far
        .binary_search_by(|token| token.range.start.cmp(&gren_syntax_comment_node.range.start))
        .unwrap_or_else(|i| i);
    match gren_syntax_comment_node.value.kind {
        GrenSyntaxCommentKind::UntilLinebreak => {
            highlighted_so_far.insert(
                insert_index,
                GrenSyntaxNode {
                    range: gren_syntax_comment_node.range,
                    value: GrenSyntaxHighlightKind::Comment,
                },
            );
        }
        GrenSyntaxCommentKind::Block => {
            highlighted_so_far.splice(
                insert_index..insert_index,
                gren_syntax_highlight_multi_line(
                    GrenSyntaxNode {
                        range: gren_syntax_comment_node.range,
                        value: &gren_syntax_comment_node.value.content,
                    },
                    2,
                    2,
                )
                .map(|range| GrenSyntaxNode {
                    range: range,
                    value: GrenSyntaxHighlightKind::Comment,
                }),
            );
        }
    }
}
fn gren_syntax_highlight_multi_line(
    gren_syntax_str_node: GrenSyntaxNode<&str>,
    characters_before_content: usize,
    characters_after_content: usize,
) -> impl Iterator<Item = lsp_types::Range> {
    let content_does_not_break_line: bool =
        gren_syntax_str_node.range.start.line == gren_syntax_str_node.range.end.line;
    gren_syntax_str_node
        .value
        .lines()
        .chain(
            // str::lines() eats the last linebreak. Restore it
            if gren_syntax_str_node.value.ends_with("\n") {
                Some("\n")
            } else {
                None
            },
        )
        .enumerate()
        .map(move |(inner_line, inner_line_str)| {
            let line: u32 = gren_syntax_str_node.range.start.line + (inner_line as u32);
            let line_length_utf16: usize = inner_line_str.encode_utf16().count();
            if inner_line == 0 {
                lsp_types::Range {
                    start: gren_syntax_str_node.range.start,
                    end: lsp_position_add_characters(
                        gren_syntax_str_node.range.start,
                        (characters_before_content
                            + line_length_utf16
                            + if content_does_not_break_line {
                                characters_after_content
                            } else {
                                0
                            }) as i32,
                    ),
                }
            } else {
                lsp_types::Range {
                    start: lsp_types::Position {
                        line: line,
                        character: 0,
                    },
                    end: if line == gren_syntax_str_node.range.end.line {
                        gren_syntax_str_node.range.end
                    } else {
                        lsp_types::Position {
                            line: line,
                            character: (line_length_utf16 + characters_after_content) as u32,
                        }
                    },
                }
            }
        })
}

fn gren_syntax_highlight_import_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_import_node: GrenSyntaxNode<&GrenSyntaxImport>,
) {
    highlighted_so_far.push(GrenSyntaxNode {
        range: lsp_types::Range {
            start: gren_syntax_import_node.range.start,
            end: lsp_position_add_characters(gren_syntax_import_node.range.start, 6),
        },
        value: GrenSyntaxHighlightKind::KeySymbol,
    });
    if let Some(module_name_node) = &gren_syntax_import_node.value.module_name {
        highlighted_so_far.push(GrenSyntaxNode {
            range: module_name_node.range,
            value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
        });
    }
    if let Some(as_keyword_range) = gren_syntax_import_node.value.as_keyword_range {
        highlighted_so_far.push(GrenSyntaxNode {
            range: as_keyword_range,
            value: GrenSyntaxHighlightKind::KeySymbol,
        });
    }
    if let Some(alias_name_node) = &gren_syntax_import_node.value.alias_name {
        highlighted_so_far.push(GrenSyntaxNode {
            range: alias_name_node.range,
            value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
        });
    }
    if let Some(exposing_keyword_range) = gren_syntax_import_node.value.exposing_keyword_range {
        highlighted_so_far.push(GrenSyntaxNode {
            range: exposing_keyword_range,
            value: GrenSyntaxHighlightKind::KeySymbol,
        });
    }
    if let Some(exposing_node) = &gren_syntax_import_node.value.exposing {
        gren_syntax_highlight_exposing_into(highlighted_so_far, &exposing_node.value);
    }
}

fn gren_syntax_highlight_exposing_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_exposing: &GrenSyntaxExposing,
) {
    match gren_syntax_exposing {
        GrenSyntaxExposing::All(ellipsis_range) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: *ellipsis_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
        }
        GrenSyntaxExposing::Explicit(exposes) => {
            for expose_node in exposes {
                match &expose_node.value {
                    GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                        name: type_name_node,
                        open_range: maybe_open_range,
                    } => {
                        highlighted_so_far.push(GrenSyntaxNode {
                            range: type_name_node.range,
                            value: GrenSyntaxHighlightKind::Type,
                        });
                        if let &Some(open_range) = maybe_open_range {
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: open_range,
                                value: GrenSyntaxHighlightKind::Variant,
                            });
                        }
                    }
                    GrenSyntaxExpose::Operator(maybe_operator) => {
                        if let Some(operator_node) = maybe_operator {
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: operator_node.range,
                                value: GrenSyntaxHighlightKind::Operator,
                            });
                        }
                    }
                    GrenSyntaxExpose::Type(_) => {
                        highlighted_so_far.push(GrenSyntaxNode {
                            range: expose_node.range,
                            value: GrenSyntaxHighlightKind::Type,
                        });
                    }
                    GrenSyntaxExpose::Variable(_) => {
                        highlighted_so_far.push(GrenSyntaxNode {
                            range: expose_node.range,
                            value: GrenSyntaxHighlightKind::DeclaredVariable,
                        });
                    }
                }
            }
        }
    }
}

fn gren_syntax_highlight_declaration_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_declaration_node: GrenSyntaxNode<&GrenSyntaxDeclaration>,
) {
    match gren_syntax_declaration_node.value {
        GrenSyntaxDeclaration::Variable {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: start_name_node.range,
                value: GrenSyntaxHighlightKind::DeclaredVariable,
            });
            if let Some(signature) = maybe_signature {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: signature.colon_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                if let Some(signature_type_node) = &signature.type_ {
                    gren_syntax_highlight_type_into(
                        highlighted_so_far,
                        gren_syntax_node_as_ref(signature_type_node),
                    );
                }
                if let Some(implementation_name_range) = signature.implementation_name_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: implementation_name_range,
                        value: GrenSyntaxHighlightKind::DeclaredVariable,
                    });
                }
            }
            for parameter_node in parameters {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(parameter_node),
                );
            }
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(result_node) = maybe_result {
                let mut local_bindings: Vec<GrenLocalBinding> = Vec::new();
                for parameter_node in parameters {
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                }
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    &local_bindings,
                    gren_syntax_node_as_ref(result_node),
                );
            }
        }
        GrenSyntaxDeclaration::ChoiceType {
            name: maybe_name,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            variant0_name: maybe_variant0_name,
            variant0_value: variant0_maybe_value,
            variant1_up,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_declaration_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_declaration_node.range.start, 4),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(name_node) = maybe_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: name_node.range,
                    value: GrenSyntaxHighlightKind::Type,
                });
            }
            for parameter_name_node in parameters {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: parameter_name_node.range,
                    value: GrenSyntaxHighlightKind::TypeVariable,
                });
            }
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(variant0_name_node) = maybe_variant0_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: variant0_name_node.range,
                    value: GrenSyntaxHighlightKind::Variant,
                });
            }
            if let Some(variant0_value_node) = variant0_maybe_value {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(variant0_value_node),
                );
            }
            for variant in variant1_up {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: variant.or_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                if let Some(variant_name_node) = &variant.name {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: variant_name_node.range,
                        value: GrenSyntaxHighlightKind::Variant,
                    });
                }
                if let Some(variant_value_node) = &variant.value {
                    gren_syntax_highlight_type_into(
                        highlighted_so_far,
                        gren_syntax_node_as_ref(variant_value_node),
                    );
                }
            }
        }
        GrenSyntaxDeclaration::Operator {
            direction: maybe_direction,
            precedence: maybe_precedence,
            operator: maybe_operator,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            function: maybe_function_name,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_declaration_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_declaration_node.range.start, 5),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(direction_node) = maybe_direction {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: direction_node.range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(precedence_node) = maybe_precedence {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: precedence_node.range,
                    value: GrenSyntaxHighlightKind::Number,
                });
            }
            if let Some(operator_node) = maybe_operator {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: operator_node.range,
                    value: GrenSyntaxHighlightKind::Operator,
                });
            }
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(function_name_node) = maybe_function_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: function_name_node.range,
                    value: GrenSyntaxHighlightKind::DeclaredVariable,
                });
            }
        }
        GrenSyntaxDeclaration::Port {
            name: maybe_name,
            colon_key_symbol_range: maybe_colon_key_symbol_range,
            type_: maybe_type,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_declaration_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_declaration_node.range.start, 4),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(name_node) = maybe_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: name_node.range,
                    value: GrenSyntaxHighlightKind::DeclaredVariable,
                });
            }
            if let &Some(colon_key_symbol_range) = maybe_colon_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: colon_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(type_node) = maybe_type {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(type_node),
                );
            }
        }
        GrenSyntaxDeclaration::TypeAlias {
            alias_keyword_range,
            name: maybe_name,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            type_: maybe_type,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_declaration_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_declaration_node.range.start, 4),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            highlighted_so_far.push(GrenSyntaxNode {
                range: *alias_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(name_node) = maybe_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: name_node.range,
                    value: GrenSyntaxHighlightKind::Type,
                });
            }
            for parameter_name_node in parameters {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: parameter_name_node.range,
                    value: GrenSyntaxHighlightKind::TypeVariable,
                });
            }
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(type_node) = maybe_type {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(type_node),
                );
            }
        }
    }
}

fn gren_syntax_highlight_qualified_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    qualified_node: GrenSyntaxNode<GrenQualified>,
    kind: GrenSyntaxHighlightKind,
) {
    if qualified_node.value.qualification.is_empty() {
        highlighted_so_far.push(GrenSyntaxNode {
            range: qualified_node.range,
            value: kind,
        });
    } else {
        let name_start_position: lsp_types::Position = lsp_position_add_characters(
            qualified_node.range.end,
            -(qualified_node.value.name.encode_utf16().count() as i32),
        );
        highlighted_so_far.push(GrenSyntaxNode {
            range: lsp_types::Range {
                start: qualified_node.range.start,
                end: name_start_position,
            },
            value: GrenSyntaxHighlightKind::ModuleNameOrAlias,
        });
        highlighted_so_far.push(GrenSyntaxNode {
            range: lsp_types::Range {
                start: name_start_position,
                end: qualified_node.range.end,
            },
            value: kind,
        });
    }
}
fn gren_syntax_highlight_pattern_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_pattern_node: GrenSyntaxNode<&GrenSyntaxPattern>,
) {
    match gren_syntax_pattern_node.value {
        GrenSyntaxPattern::As {
            pattern: alias_pattern_node,
            as_keyword_range,
            variable: maybe_variable,
        } => {
            gren_syntax_highlight_pattern_into(
                highlighted_so_far,
                gren_syntax_node_unbox(alias_pattern_node),
            );
            highlighted_so_far.push(GrenSyntaxNode {
                range: *as_keyword_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(variable_node) = maybe_variable {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: variable_node.range,
                    value: GrenSyntaxHighlightKind::Variable,
                });
            }
        }
        GrenSyntaxPattern::Char(_) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_pattern_node.range,
                value: GrenSyntaxHighlightKind::String,
            });
        }
        GrenSyntaxPattern::Ignored(maybe_name) => match maybe_name {
            None => {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: gren_syntax_pattern_node.range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            Some(_) => {
                let name_start: lsp_types::Position =
                    lsp_position_add_characters(gren_syntax_pattern_node.range.start, 1);
                highlighted_so_far.push(GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: gren_syntax_pattern_node.range.start,
                        end: name_start,
                    },
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                highlighted_so_far.push(GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: name_start,
                        end: gren_syntax_pattern_node.range.end,
                    },
                    value: GrenSyntaxHighlightKind::Comment,
                });
            }
        },
        GrenSyntaxPattern::Int { .. } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_pattern_node.range,
                value: GrenSyntaxHighlightKind::Number,
            });
        }
        GrenSyntaxPattern::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_unbox(in_parens),
                );
            }
        }
        GrenSyntaxPattern::Record(fields) => {
            for field in fields {
                match &field.value {
                    None => match field.equals_key_symbol_range {
                        None => {
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: field.name.range,
                                value: GrenSyntaxHighlightKind::Variable,
                            });
                        }
                        Some(equals_key_symbol_range) => {
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: equals_key_symbol_range,
                                value: GrenSyntaxHighlightKind::Field,
                            });
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: field.name.range,
                                value: GrenSyntaxHighlightKind::Field,
                            });
                        }
                    },
                    Some(field_value) => {
                        highlighted_so_far.push(GrenSyntaxNode {
                            range: field.name.range,
                            value: GrenSyntaxHighlightKind::Field,
                        });
                        if let Some(equals_key_symbol_range) = field.equals_key_symbol_range {
                            highlighted_so_far.push(GrenSyntaxNode {
                                range: equals_key_symbol_range,
                                value: GrenSyntaxHighlightKind::Field,
                            });
                        }
                        gren_syntax_highlight_pattern_into(
                            highlighted_so_far,
                            gren_syntax_node_as_ref(field_value),
                        );
                    }
                }
            }
        }
        GrenSyntaxPattern::String {
            content: _,
            quoting_style: _,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_pattern_node.range,
                value: GrenSyntaxHighlightKind::String,
            });
        }
        GrenSyntaxPattern::Variable(_) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_pattern_node.range,
                value: GrenSyntaxHighlightKind::Variable,
            });
        }
        GrenSyntaxPattern::Variant {
            reference: reference_node,
            value: values,
        } => {
            gren_syntax_highlight_qualified_into(
                highlighted_so_far,
                GrenSyntaxNode {
                    range: reference_node.range,
                    value: GrenQualified {
                        qualification: &reference_node.value.qualification,
                        name: &reference_node.value.name,
                    },
                },
                GrenSyntaxHighlightKind::Variant,
            );
            if let Some(value_node) = values {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_unbox(value_node),
                );
            }
        }
    }
}
fn gren_syntax_highlight_type_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    gren_syntax_type_node: GrenSyntaxNode<&GrenSyntaxType>,
) {
    match gren_syntax_type_node.value {
        GrenSyntaxType::Construct {
            reference: reference_node,
            arguments,
        } => {
            gren_syntax_highlight_qualified_into(
                highlighted_so_far,
                GrenSyntaxNode {
                    range: reference_node.range,
                    value: GrenQualified {
                        qualification: &reference_node.value.qualification,
                        name: &reference_node.value.name,
                    },
                },
                GrenSyntaxHighlightKind::Type,
            );
            for argument_node in arguments {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(argument_node),
                );
            }
        }
        GrenSyntaxType::Function {
            input,
            arrow_key_symbol_range,
            output: maybe_output,
        } => {
            gren_syntax_highlight_type_into(highlighted_so_far, gren_syntax_node_unbox(input));
            highlighted_so_far.push(GrenSyntaxNode {
                range: *arrow_key_symbol_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(output_node) = maybe_output {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_unbox(output_node),
                );
            }
        }
        GrenSyntaxType::Parenthesized(maybe_n_parens) => {
            if let Some(in_parens) = maybe_n_parens {
                gren_syntax_highlight_type_into(
                    highlighted_so_far,
                    gren_syntax_node_unbox(in_parens),
                );
            }
        }
        GrenSyntaxType::Record(fields) => {
            for field in fields {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: field.name.range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                if let Some(colon_key_symbol_range) = field.colon_key_symbol_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: colon_key_symbol_range,
                        value: GrenSyntaxHighlightKind::KeySymbol,
                    });
                }
                if let Some(field_value_node) = &field.value {
                    gren_syntax_highlight_type_into(
                        highlighted_so_far,
                        gren_syntax_node_as_ref(field_value_node),
                    );
                }
            }
        }
        GrenSyntaxType::RecordExtension {
            record_variable: maybe_record_variable,
            bar_key_symbol_range,
            fields,
        } => {
            if let Some(record_variable_node) = maybe_record_variable {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: record_variable_node.range,
                    value: GrenSyntaxHighlightKind::TypeVariable,
                });
            }
            highlighted_so_far.push(GrenSyntaxNode {
                range: *bar_key_symbol_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            for field in fields {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: field.name.range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                if let Some(colon_key_symbol_range) = field.colon_key_symbol_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: colon_key_symbol_range,
                        value: GrenSyntaxHighlightKind::KeySymbol,
                    });
                }
                if let Some(field_value_node) = &field.value {
                    gren_syntax_highlight_type_into(
                        highlighted_so_far,
                        gren_syntax_node_as_ref(field_value_node),
                    );
                }
            }
        }
        GrenSyntaxType::Variable(_) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_type_node.range,
                value: GrenSyntaxHighlightKind::TypeVariable,
            });
        }
    }
}

fn gren_syntax_highlight_expression_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    local_bindings: &[GrenLocalBinding],
    gren_syntax_expression_node: GrenSyntaxNode<&GrenSyntaxExpression>,
) {
    match gren_syntax_expression_node.value {
        GrenSyntaxExpression::Call {
            called,
            argument0,
            argument1_up,
        } => {
            gren_syntax_highlight_expression_into(
                highlighted_so_far,
                local_bindings,
                gren_syntax_node_unbox(called),
            );
            gren_syntax_highlight_expression_into(
                highlighted_so_far,
                local_bindings,
                gren_syntax_node_unbox(argument0),
            );
            for argument_node in argument1_up {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_as_ref(argument_node),
                );
            }
        }
        GrenSyntaxExpression::CaseOf {
            matched: maybe_matched,
            of_keyword_range: maybe_of_keyword_range,
            cases,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_expression_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_expression_node.range.start, 4),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(matched_node) = maybe_matched {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(matched_node),
                );
            }
            if let &Some(of_keyword_range) = maybe_of_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: of_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            for case in cases {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(&case.pattern),
                );
                if let Some(arrow_key_symbol_range) = case.arrow_key_symbol_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: arrow_key_symbol_range,
                        value: GrenSyntaxHighlightKind::KeySymbol,
                    });
                }
                if let Some(result_node) = &case.result {
                    let mut local_bindings: Vec<GrenLocalBinding> = local_bindings.to_vec();
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings,
                        gren_syntax_node_as_ref(&case.pattern),
                    );
                    gren_syntax_highlight_expression_into(
                        highlighted_so_far,
                        &local_bindings,
                        gren_syntax_node_as_ref(result_node),
                    );
                }
            }
        }
        GrenSyntaxExpression::Char(_) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_expression_node.range,
                value: GrenSyntaxHighlightKind::String,
            });
        }
        GrenSyntaxExpression::Float(_) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_expression_node.range,
                value: GrenSyntaxHighlightKind::Number,
            });
        }
        GrenSyntaxExpression::IfThenElse {
            condition: maybe_condition,
            then_keyword_range: maybe_then_keyword_range,
            on_true: maybe_on_true,
            else_keyword_range: maybe_else_keyword_range,
            on_false: maybe_on_false,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_expression_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_expression_node.range.start, 2),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(condition_node) = maybe_condition {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(condition_node),
                );
            }
            if let &Some(then_keyword_range) = maybe_then_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: then_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(on_true_node) = maybe_on_true {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(on_true_node),
                );
            }
            if let Some(else_keyword_range) = maybe_else_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: *else_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(on_false_node) = maybe_on_false {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(on_false_node),
                );
            }
        }
        GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
            left,
            operator: operator_node,
            right: maybe_right,
        } => {
            gren_syntax_highlight_expression_into(
                highlighted_so_far,
                local_bindings,
                gren_syntax_node_unbox(left),
            );
            highlighted_so_far.push(GrenSyntaxNode {
                range: operator_node.range,
                value: GrenSyntaxHighlightKind::Operator,
            });
            if let Some(right_node) = maybe_right {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(right_node),
                );
            }
        }
        GrenSyntaxExpression::Integer { .. } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: gren_syntax_expression_node.range,
                value: GrenSyntaxHighlightKind::Number,
            });
        }
        GrenSyntaxExpression::Lambda {
            parameters,
            arrow_key_symbol_range: maybe_arrow_key_symbol_range,
            result: maybe_result,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_expression_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_expression_node.range.start, 1),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            for parameter_node in parameters {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(parameter_node),
                );
            }
            if let &Some(arrow_key_symbol_range) = maybe_arrow_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: arrow_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(result_node) = maybe_result {
                let mut local_bindings: Vec<GrenLocalBinding> = local_bindings.to_vec();
                for parameter_node in parameters {
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                }
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    &local_bindings,
                    gren_syntax_node_unbox(result_node),
                );
            }
        }
        GrenSyntaxExpression::LetIn {
            declarations,
            in_keyword_range: maybe_in_keyword_range,
            result: maybe_result,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_expression_node.range.start,
                    end: lsp_position_add_characters(gren_syntax_expression_node.range.start, 3),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            let mut local_bindings: Vec<GrenLocalBinding> = local_bindings.to_vec();
            for let_declaration_node in declarations {
                gren_syntax_let_declaration_introduced_bindings_into(
                    &mut local_bindings,
                    &let_declaration_node.value,
                );
            }
            for let_declaration_node in declarations {
                gren_syntax_highlight_let_declaration_into(
                    highlighted_so_far,
                    &local_bindings,
                    gren_syntax_node_as_ref(let_declaration_node),
                );
            }
            if let &Some(in_keyword_range) = maybe_in_keyword_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: in_keyword_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(result_node) = maybe_result {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    &local_bindings,
                    gren_syntax_node_unbox(result_node),
                );
            }
        }
        GrenSyntaxExpression::Array(elements) => {
            for element_node in elements {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_as_ref(element_node),
                );
            }
        }
        GrenSyntaxExpression::Negation(maybe_in_negation) => {
            if let Some(in_negation_node) = maybe_in_negation {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(in_negation_node),
                );
            }
        }
        GrenSyntaxExpression::OperatorFunction(operator_node) => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: operator_node.range,
                value: GrenSyntaxHighlightKind::Operator,
            });
        }
        GrenSyntaxExpression::Parenthesized(maybe_in_parens) => {
            if let Some(in_parens) = maybe_in_parens {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_unbox(in_parens),
                );
            }
        }
        GrenSyntaxExpression::Record(fields) => {
            for field in fields {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: field.name.range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                if let Some(equals_key_symbol_range) = field.equals_key_symbol_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: equals_key_symbol_range,
                        value: GrenSyntaxHighlightKind::KeySymbol,
                    });
                }
                if let Some(value_node) = &field.value {
                    gren_syntax_highlight_expression_into(
                        highlighted_so_far,
                        local_bindings,
                        gren_syntax_node_as_ref(value_node),
                    );
                }
            }
        }
        GrenSyntaxExpression::RecordAccess {
            record: record_node,
            field: maybe_field_name,
        } => {
            gren_syntax_highlight_expression_into(
                highlighted_so_far,
                local_bindings,
                gren_syntax_node_unbox(record_node),
            );
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: record_node.range.end,
                    end: lsp_position_add_characters(record_node.range.end, 1),
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            if let Some(field_name_node) = maybe_field_name {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: field_name_node.range,
                    value: GrenSyntaxHighlightKind::Field,
                });
            }
        }
        GrenSyntaxExpression::RecordAccessFunction(_) => {
            let field_name_start_position: lsp_types::Position =
                lsp_position_add_characters(gren_syntax_expression_node.range.start, 1);
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: gren_syntax_expression_node.range.start,
                    end: field_name_start_position,
                },
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            highlighted_so_far.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: field_name_start_position,
                    end: gren_syntax_expression_node.range.end,
                },
                value: GrenSyntaxHighlightKind::Field,
            });
        }
        GrenSyntaxExpression::RecordUpdate {
            record_variable: maybe_record_variable,
            bar_key_symbol_range,
            fields,
        } => {
            if let Some(record_variable_node) = maybe_record_variable {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: record_variable_node.range,
                    value: GrenSyntaxHighlightKind::Variable,
                });
            }
            highlighted_so_far.push(GrenSyntaxNode {
                range: *bar_key_symbol_range,
                value: GrenSyntaxHighlightKind::KeySymbol,
            });
            for field in fields {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: field.name.range,
                    value: GrenSyntaxHighlightKind::Field,
                });
                if let Some(equals_key_symbol_range) = field.equals_key_symbol_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: equals_key_symbol_range,
                        value: GrenSyntaxHighlightKind::KeySymbol,
                    });
                }
                if let Some(value_node) = &field.value {
                    gren_syntax_highlight_expression_into(
                        highlighted_so_far,
                        local_bindings,
                        gren_syntax_node_as_ref(value_node),
                    );
                }
            }
        }
        GrenSyntaxExpression::Reference {
            qualification,
            name,
        } => {
            if qualification.is_empty()
                && let Some(origin_binding) = local_bindings
                    .iter()
                    .find(|bind| bind.name == name.as_ref())
            {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: gren_syntax_expression_node.range,
                    value: match origin_binding.origin {
                        LocalBindingOrigin::PatternVariable(_) => GrenSyntaxHighlightKind::Variable,
                        LocalBindingOrigin::PatternRecordField(_) => {
                            GrenSyntaxHighlightKind::Variable
                        }
                        LocalBindingOrigin::LetDeclaredVariable { .. } => {
                            GrenSyntaxHighlightKind::DeclaredVariable
                        }
                    },
                });
            } else {
                gren_syntax_highlight_qualified_into(
                    highlighted_so_far,
                    GrenSyntaxNode {
                        range: gren_syntax_expression_node.range,
                        value: GrenQualified {
                            qualification: qualification.as_ref(),
                            name: name.as_ref(),
                        },
                    },
                    if name.starts_with(|c: char| c.is_uppercase()) {
                        GrenSyntaxHighlightKind::Variant
                    } else {
                        GrenSyntaxHighlightKind::DeclaredVariable
                    },
                );
            }
        }
        GrenSyntaxExpression::String {
            content,
            quoting_style,
        } => {
            let quote_count: usize = match quoting_style {
                GrenSyntaxStringQuotingStyle::SingleQuoted => 1,
                GrenSyntaxStringQuotingStyle::TripleQuoted => 3,
            };
            highlighted_so_far.extend(
                gren_syntax_highlight_multi_line(
                    GrenSyntaxNode {
                        range: gren_syntax_expression_node.range,
                        value: content,
                    },
                    quote_count,
                    quote_count,
                )
                .map(|range| GrenSyntaxNode {
                    range: range,
                    value: GrenSyntaxHighlightKind::String,
                }),
            );
        }
    }
}

fn gren_syntax_highlight_let_declaration_into(
    highlighted_so_far: &mut Vec<GrenSyntaxNode<GrenSyntaxHighlightKind>>,
    local_bindings: &[GrenLocalBinding],
    gren_syntax_let_declaration_node: GrenSyntaxNode<&GrenSyntaxLetDeclaration>,
) {
    match gren_syntax_let_declaration_node.value {
        GrenSyntaxLetDeclaration::Destructuring {
            pattern: destructuring_pattern_node,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            expression: maybe_destructured_expression,
        } => {
            gren_syntax_highlight_pattern_into(
                highlighted_so_far,
                gren_syntax_node_as_ref(destructuring_pattern_node),
            );
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(destructured_expression_node) = maybe_destructured_expression {
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    local_bindings,
                    gren_syntax_node_as_ref(destructured_expression_node),
                );
            }
        }
        GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        } => {
            highlighted_so_far.push(GrenSyntaxNode {
                range: start_name_node.range,
                value: GrenSyntaxHighlightKind::DeclaredVariable,
            });
            if let Some(signature) = maybe_signature {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: signature.colon_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
                if let Some(signature_type_node) = &signature.type_ {
                    gren_syntax_highlight_type_into(
                        highlighted_so_far,
                        gren_syntax_node_as_ref(signature_type_node),
                    );
                }
                if let Some(implementation_name_range) = signature.implementation_name_range {
                    highlighted_so_far.push(GrenSyntaxNode {
                        range: implementation_name_range,
                        value: GrenSyntaxHighlightKind::DeclaredVariable,
                    });
                }
            }
            for parameter_node in parameters {
                gren_syntax_highlight_pattern_into(
                    highlighted_so_far,
                    gren_syntax_node_as_ref(parameter_node),
                );
            }
            if let &Some(equals_key_symbol_range) = maybe_equals_key_symbol_range {
                highlighted_so_far.push(GrenSyntaxNode {
                    range: equals_key_symbol_range,
                    value: GrenSyntaxHighlightKind::KeySymbol,
                });
            }
            if let Some(result_node) = maybe_result {
                let mut local_bindings: Vec<GrenLocalBinding> = local_bindings.to_vec();
                for parameter_node in parameters {
                    gren_syntax_pattern_bindings_into(
                        &mut local_bindings,
                        gren_syntax_node_as_ref(parameter_node),
                    );
                }
                gren_syntax_highlight_expression_into(
                    highlighted_so_far,
                    &local_bindings,
                    gren_syntax_node_as_ref(result_node),
                );
            }
        }
    }
}

// //
struct ParseState<'a> {
    source: &'a str,
    offset_utf8: usize,
    position: lsp_types::Position,
    indent: u16,
    lower_indents_stack: Vec<u16>,
    comments: Vec<GrenSyntaxNode<GrenSyntaxComment>>,
}
#[derive(Clone, Debug, PartialEq)]
struct GrenSyntaxComment {
    kind: GrenSyntaxCommentKind,
    content: Box<str>,
}
#[derive(Clone, Debug, PartialEq)]
enum GrenSyntaxCommentKind {
    /// --
    UntilLinebreak,
    /// {- ... -}
    Block,
}

fn parse_state_push_indent(state: &mut ParseState, new_indent: u16) {
    state.lower_indents_stack.push(state.indent);
    state.indent = new_indent;
}
fn parse_state_pop_indent(state: &mut ParseState) {
    state.indent = state.lower_indents_stack.pop().unwrap_or(0);
}

fn str_starts_with_linebreak(str: &str) -> bool {
    // \r allowed because both \r and \r\n are counted as linebreak
    // see EOL in https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocuments
    str.starts_with("\n") || str.starts_with("\r")
}
fn parse_linebreak(state: &mut ParseState) -> bool {
    // see EOL in https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocuments
    if state.source[state.offset_utf8..].starts_with("\n") {
        state.offset_utf8 += 1;
        state.position.line += 1;
        state.position.character = 0;
        true
    } else if state.source[state.offset_utf8..].starts_with("\r\n") {
        state.offset_utf8 += 2;
        state.position.line += 1;
        state.position.character = 0;
        true
    } else if state.source[state.offset_utf8..].starts_with("\r") {
        state.offset_utf8 += 1;
        state.position.line += 1;
        state.position.character = 0;
        true
    } else {
        false
    }
}
fn parse_linebreak_as_str<'a>(state: &mut ParseState<'a>) -> Option<&'a str> {
    // see EOL in https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocuments
    if state.source[state.offset_utf8..].starts_with("\n") {
        state.offset_utf8 += 1;
        state.position.line += 1;
        state.position.character = 0;
        Some("\n")
    } else if state.source[state.offset_utf8..].starts_with("\r\n") {
        state.offset_utf8 += 2;
        state.position.line += 1;
        state.position.character = 0;
        Some("\r\n")
    } else if state.source[state.offset_utf8..].starts_with("\r") {
        state.offset_utf8 += 1;
        state.position.line += 1;
        state.position.character = 0;
        Some("\r")
    } else {
        None
    }
}
/// prefer using after `parse_line_break` or similar failed
fn parse_any_guaranteed_non_linebreak_char(state: &mut ParseState) -> bool {
    match state.source[state.offset_utf8..].chars().next() {
        None => false,
        Some(parsed_char) => {
            state.offset_utf8 += parsed_char.len_utf8();
            state.position.character += parsed_char.len_utf16() as u32;
            true
        }
    }
}
/// prefer using after `parse_line_break` or similar failed
fn parse_any_guaranteed_non_linebreak_char_as_char(state: &mut ParseState) -> Option<char> {
    match state.source[state.offset_utf8..].chars().next() {
        None => None,
        Some(parsed_char) => {
            state.offset_utf8 += parsed_char.len_utf8();
            state.position.character += parsed_char.len_utf16() as u32;
            Some(parsed_char)
        }
    }
}
/// symbol cannot be non-utf8 characters or \n
fn parse_char_symbol_as_char(state: &mut ParseState, symbol: char) -> Option<char> {
    if state.source[state.offset_utf8..].starts_with(symbol) {
        state.offset_utf8 += symbol.len_utf8();
        state.position.character += symbol.len_utf16() as u32;
        Some(symbol)
    } else {
        None
    }
}
/// symbol cannot contain non-utf8 characters or \n
fn parse_symbol(state: &mut ParseState, symbol: &str) -> bool {
    if state.source[state.offset_utf8..].starts_with(symbol) {
        state.offset_utf8 += symbol.len();
        state.position.character += symbol.len() as u32;
        true
    } else {
        false
    }
}
/// symbol cannot contain non-utf8 characters or \n
fn parse_symbol_as<A>(state: &mut ParseState, symbol: &'static str, result: A) -> Option<A> {
    if parse_symbol(state, symbol) {
        Some(result)
    } else {
        None
    }
}
/// symbol cannot contain non-utf8 characters or \n
fn parse_symbol_as_str(state: &mut ParseState, symbol: &'static str) -> Option<&'static str> {
    parse_symbol_as(state, symbol, symbol)
}
/// symbol cannot contain non-utf8 characters or \n
fn parse_symbol_as_range(state: &mut ParseState, symbol: &str) -> Option<lsp_types::Range> {
    let start_position: lsp_types::Position = state.position;
    if parse_symbol(state, symbol) {
        Some(lsp_types::Range {
            start: start_position,
            end: state.position,
        })
    } else {
        None
    }
}
/// given condition must not succeed on linebreak
fn parse_same_line_while(state: &mut ParseState, char_is_valid: impl Fn(char) -> bool) {
    let consumed_chars_iterator = state.source[state.offset_utf8..]
        .chars()
        .take_while(|&c| char_is_valid(c));
    let consumed_length_utf8: usize = consumed_chars_iterator.clone().map(char::len_utf8).sum();
    let consumed_length_utf16: usize = consumed_chars_iterator.clone().map(char::len_utf16).sum();
    state.offset_utf8 += consumed_length_utf8;
    state.position.character += consumed_length_utf16 as u32;
}
/// given condition must not succeed on linebreak
fn parse_same_line_while_as_str<'a>(
    state: &mut ParseState<'a>,
    char_is_valid: impl Fn(char) -> bool,
) -> &'a str {
    let start_offset_utf8: usize = state.offset_utf8;
    parse_same_line_while(state, char_is_valid);
    &state.source[start_offset_utf8..state.offset_utf8]
}
/// given condition must not succeed on linebreak
fn parse_same_line_while_at_least_one_as_node(
    state: &mut ParseState,
    char_is_valid: impl Fn(char) -> bool + Copy,
) -> Option<GrenSyntaxNode<Box<str>>> {
    let start_position: lsp_types::Position = state.position;
    let start_offset_utf8: usize = state.offset_utf8;
    if !parse_same_line_char_if(state, char_is_valid) {
        return None;
    }
    parse_same_line_while(state, char_is_valid);
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: Box::from(&state.source[start_offset_utf8..state.offset_utf8]),
    })
}
fn parse_before_next_linebreak(state: &mut ParseState) {
    parse_same_line_while(state, |c| c != '\r' && c != '\n');
}
/// given condition must not succeed on linebreak
fn parse_same_line_char_if(state: &mut ParseState, char_is_valid: impl Fn(char) -> bool) -> bool {
    if let Some(next_char) = state.source[state.offset_utf8..].chars().next()
        && char_is_valid(next_char)
    {
        state.offset_utf8 += next_char.len_utf8();
        state.position.character += next_char.len_utf16() as u32;
        true
    } else {
        false
    }
}
fn parse_unsigned_integer_base10(state: &mut ParseState) -> bool {
    if parse_symbol(state, "0") {
        true
    } else if parse_same_line_char_if(state, |c| ('1'..='9').contains(&c)) {
        parse_same_line_while(state, |c| c.is_ascii_digit());
        true
    } else {
        false
    }
}

/// a valid gren symbol that must be followed by a character that could not be part of an gren identifier
fn parse_gren_keyword_as_range(state: &mut ParseState, symbol: &str) -> Option<lsp_types::Range> {
    if state.source[state.offset_utf8..].starts_with(symbol)
        && !(state.source[(state.offset_utf8 + symbol.len())..]
            .starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    {
        let start_position: lsp_types::Position = state.position;
        state.offset_utf8 += symbol.len();
        state.position.character += symbol.len() as u32;
        Some(lsp_types::Range {
            start: start_position,
            end: state.position,
        })
    } else {
        None
    }
}

fn parse_gren_whitespace_and_comments(state: &mut ParseState) {
    while parse_linebreak(state)
        || parse_same_line_char_if(state, char::is_whitespace)
        || parse_gren_comment(state)
    {}
}
fn parse_gren_comment(state: &mut ParseState) -> bool {
    parse_gren_comment_until_linebreak(state) || parse_gren_comment_block(state)
}
fn parse_gren_comment_until_linebreak(state: &mut ParseState) -> bool {
    let position_before: lsp_types::Position = state.position;
    if !parse_symbol(state, "--") {
        return false;
    }
    let content: &str = state.source[state.offset_utf8..]
        .lines()
        .next()
        .unwrap_or("");
    state.offset_utf8 += content.len();
    state.position.character += content.encode_utf16().count() as u32;
    let full_range: lsp_types::Range = lsp_types::Range {
        start: position_before,
        end: state.position,
    };
    state.comments.push(GrenSyntaxNode {
        range: full_range,
        value: GrenSyntaxComment {
            content: Box::from(content),
            kind: GrenSyntaxCommentKind::UntilLinebreak,
        },
    });
    true
}
/// does not parse documentation comment (starting with {-|)
fn parse_gren_comment_block(state: &mut ParseState) -> bool {
    if state.source[state.offset_utf8..].starts_with("{-|") {
        return false;
    }
    let start_position: lsp_types::Position = state.position;
    if !parse_symbol(state, "{-") {
        return false;
    }
    let content_start_offset_utf8: usize = state.offset_utf8;
    let mut nesting_level: u32 = 1;
    'until_fully_unnested: loop {
        if parse_linebreak(state) {
        } else if parse_symbol(state, "{-") {
            nesting_level += 1;
        } else if parse_symbol(state, "-}") {
            if nesting_level <= 1 {
                break 'until_fully_unnested;
            }
            nesting_level -= 1;
        } else if parse_any_guaranteed_non_linebreak_char(state) {
        } else {
            // end of source
            break 'until_fully_unnested;
        }
    }
    let content_including_closing: &str =
        &state.source[content_start_offset_utf8..state.offset_utf8];
    state.comments.push(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: GrenSyntaxComment {
            content: Box::from(
                content_including_closing
                    .strip_suffix("-}")
                    .unwrap_or(content_including_closing),
            ),
            kind: GrenSyntaxCommentKind::Block,
        },
    });
    true
}
fn parse_gren_documentation_comment_block_str<'a>(state: &mut ParseState<'a>) -> Option<&'a str> {
    if !parse_symbol(state, "{-|") {
        return None;
    }
    let content_start_offset_utf8: usize = state.offset_utf8;
    let mut nesting_level: u32 = 1;
    'until_fully_unnested: loop {
        if parse_linebreak(state) {
        } else if parse_symbol(state, "{-") {
            nesting_level += 1;
        } else if parse_symbol(state, "-}") {
            if nesting_level <= 1 {
                break 'until_fully_unnested;
            }
            nesting_level -= 1;
        } else if parse_any_guaranteed_non_linebreak_char(state) {
        } else {
            // end of source
            break 'until_fully_unnested;
        }
    }
    let content_including_closing: &str =
        &state.source[content_start_offset_utf8..state.offset_utf8];
    Some(
        content_including_closing
            .strip_suffix("-}")
            .unwrap_or(content_including_closing),
    )
}
fn parse_gren_documentation_comment_block_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<Box<str>>> {
    let start_position: lsp_types::Position = state.position;
    let content: &str = parse_gren_documentation_comment_block_str(state)?;
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: Box::from(content),
    })
}
fn parse_gren_syntax_module_documentation_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<Vec<GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>>>> {
    let start_position: lsp_types::Position = state.position;
    let start_offset_utf8: usize = state.offset_utf8;
    let _content: &str = parse_gren_documentation_comment_block_str(state)?;
    let end_position: lsp_types::Position = state.position;
    let end_offset_utf8: usize = state.offset_utf8;
    // reset state to the start of the content
    state.offset_utf8 = start_offset_utf8 + 3;
    state.position = lsp_position_add_characters(start_position, 3);
    let mut parsed_content_elements: Vec<GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>> =
        Vec::new();
    let mut previous_at_docs_end_position: lsp_types::Position = state.position;
    let mut previous_at_docs_end_offset_utf8: usize = state.offset_utf8;
    'parsing_content: while state.offset_utf8 < end_offset_utf8 - 2 {
        let before_potential_at_docs_offset_utf8: usize = state.offset_utf8;
        if let Some(at_docs_key_symbol_range) = parse_symbol_as_range(state, "@docs") {
            parsed_content_elements.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: previous_at_docs_end_position,
                    end: at_docs_key_symbol_range.start,
                },
                value: GrenSyntaxModuleDocumentationElement::Markdown(Box::from(
                    &state.source
                        [previous_at_docs_end_offset_utf8..before_potential_at_docs_offset_utf8],
                )),
            });
            let mut member_names: Vec<GrenSyntaxNode<Box<str>>> = Vec::new();
            'parsing_at_docs_member_names: loop {
                if let Some(expose_name_node) =
                    parse_same_line_while_at_least_one_as_node(state, |c| {
                        c != ',' && (c.is_alphanumeric() || c.is_ascii_punctuation())
                    })
                {
                    member_names.push(expose_name_node);
                } else if (state.source[state.offset_utf8..].starts_with('\n')
                    && !state.source[state.offset_utf8..]
                        .chars()
                        .skip(1)
                        .next()
                        .is_some_and(|c| c.is_ascii_whitespace()))
                    || (state.source[state.offset_utf8..].starts_with("\r\n")
                        && !state.source[state.offset_utf8..]
                            .chars()
                            .skip(2)
                            .next()
                            .is_some_and(|c| c.is_ascii_whitespace()))
                    || (state.offset_utf8 >= end_offset_utf8 - 2)
                    || !(parse_linebreak(state) || parse_any_guaranteed_non_linebreak_char(state))
                {
                    break 'parsing_at_docs_member_names;
                }
            }
            parsed_content_elements.push(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: at_docs_key_symbol_range.start,
                    end: state.position,
                },
                value: GrenSyntaxModuleDocumentationElement::AtDocs(member_names),
            });
            previous_at_docs_end_position = state.position;
            previous_at_docs_end_offset_utf8 = state.offset_utf8;
        } else {
            if !(parse_linebreak(state) || parse_any_guaranteed_non_linebreak_char(state)) {
                break 'parsing_content;
            }
        }
    }
    parsed_content_elements.push(GrenSyntaxNode {
        range: lsp_types::Range {
            start: previous_at_docs_end_position,
            end: state.position,
        },
        value: GrenSyntaxModuleDocumentationElement::Markdown(Box::from(
            &state.source[previous_at_docs_end_offset_utf8..state.offset_utf8],
        )),
    });
    state.position = end_position;
    state.offset_utf8 = end_offset_utf8;
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: parsed_content_elements,
    })
}
fn parse_gren_lowercase_as_box_str(state: &mut ParseState) -> Option<Box<str>> {
    let mut chars_from_offset: std::str::Chars = state.source[state.offset_utf8..].chars();
    if let Some(first_char) = chars_from_offset.next()
        && first_char.is_lowercase()
    {
        let parsed_length: usize = first_char.len_utf8()
            + chars_from_offset
                .take_while(|&c| c.is_alphanumeric() || c == '_')
                .map(char::len_utf8)
                .sum::<usize>();
        let end_offset_utf8: usize = state.offset_utf8 + parsed_length;
        let parsed_str: &str = &state.source[state.offset_utf8..end_offset_utf8];
        state.offset_utf8 = end_offset_utf8;
        state.position.character += parsed_str.encode_utf16().count() as u32;
        Some(Box::from(parsed_str))
    } else {
        None
    }
}
fn parse_gren_lowercase_as_node(state: &mut ParseState) -> Option<GrenSyntaxNode<Box<str>>> {
    let start_position: lsp_types::Position = state.position;
    parse_gren_lowercase_as_box_str(state).map(|name| GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: name,
    })
}
fn parse_gren_uppercase(state: &mut ParseState) -> Option<Box<str>> {
    let mut chars_from_offset = state.source[state.offset_utf8..].chars();
    if let Some(first_char) = chars_from_offset.next()
        && first_char.is_uppercase()
    {
        let parsed_length: usize = first_char.len_utf8()
            + chars_from_offset
                .take_while(|&c| c.is_alphanumeric() || c == '_')
                .map(char::len_utf8)
                .sum::<usize>();
        let end_offset_utf8: usize = state.offset_utf8 + parsed_length;
        let parsed_str: &str = &state.source[state.offset_utf8..end_offset_utf8];
        state.offset_utf8 = end_offset_utf8;
        state.position.character += parsed_str.encode_utf16().count() as u32;
        Some(Box::from(parsed_str))
    } else {
        None
    }
}
fn parse_gren_uppercase_node(state: &mut ParseState) -> Option<GrenSyntaxNode<Box<str>>> {
    let start_position: lsp_types::Position = state.position;
    parse_gren_uppercase(state).map(|name| GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: name,
    })
}
fn parse_gren_standalone_module_name_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<Box<str>>> {
    // very lenient, even allowing lowercase in most places it's usually forbidden
    // to allow for more convenient autocomplete without pressing shift
    let start_offset_utf8: usize = state.offset_utf8;
    let start_position: lsp_types::Position = state.position;
    if !parse_same_line_char_if(state, char::is_alphabetic) {
        return None;
    }
    parse_same_line_while(state, |c| c.is_alphanumeric() || c == '_' || c == '.');
    let parsed_name_node: GrenSyntaxNode<Box<str>> = GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: Box::from(&state.source[start_offset_utf8..state.offset_utf8]),
    };
    Some(parsed_name_node)
}
fn parse_gren_operator_node(state: &mut ParseState) -> Option<GrenSyntaxNode<&'static str>> {
    // can be optimized by only slicing once for each symbol length
    let start_position: lsp_types::Position = state.position;
    parse_symbol_as_str(state, "==")
        .or_else(|| parse_symbol_as_str(state, "!="))
        .or_else(|| parse_symbol_as_str(state, "++"))
        .or_else(|| parse_symbol_as_str(state, "<|"))
        .or_else(|| parse_symbol_as_str(state, "|>"))
        .or_else(|| parse_symbol_as_str(state, "<<"))
        .or_else(|| parse_symbol_as_str(state, ">>"))
        .or_else(|| parse_symbol_as_str(state, "||"))
        .or_else(|| parse_symbol_as_str(state, "&&"))
        .or_else(|| parse_symbol_as_str(state, "<="))
        .or_else(|| parse_symbol_as_str(state, ">="))
        .or_else(|| parse_symbol_as_str(state, "//"))
        .or_else(|| parse_symbol_as_str(state, "<"))
        .or_else(|| parse_symbol_as_str(state, ">"))
        .or_else(|| parse_symbol_as_str(state, "+"))
        .or_else(|| parse_symbol_as_str(state, "-"))
        .or_else(|| parse_symbol_as_str(state, "*"))
        .or_else(|| parse_symbol_as_str(state, "/"))
        .or_else(|| parse_symbol_as_str(state, "^"))
        .map(|parsed_symbol| GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: parsed_symbol,
        })
}
fn parse_gren_operator_followed_by_closing_paren(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<&'static str>> {
    // can be optimized by only slicing once for each symbol length
    let start_position: lsp_types::Position = state.position;
    parse_symbol_as(state, "==)", "==")
        .or_else(|| parse_symbol_as(state, "!=)", "!="))
        .or_else(|| parse_symbol_as(state, "++)", "++"))
        .or_else(|| parse_symbol_as(state, "<|)", "<|"))
        .or_else(|| parse_symbol_as(state, "|>)", "|>"))
        .or_else(|| parse_symbol_as(state, "<<)", "<<"))
        .or_else(|| parse_symbol_as(state, ">>)", ">>"))
        .or_else(|| parse_symbol_as(state, "||)", "||"))
        .or_else(|| parse_symbol_as(state, "&&)", "&&"))
        .or_else(|| parse_symbol_as(state, "<=)", "<="))
        .or_else(|| parse_symbol_as(state, ">=)", ">="))
        .or_else(|| parse_symbol_as(state, "//)", "//"))
        .or_else(|| parse_symbol_as(state, "<)", "<"))
        .or_else(|| parse_symbol_as(state, ">)", ">"))
        .or_else(|| parse_symbol_as(state, "+)", "+"))
        .or_else(|| parse_symbol_as(state, "-)", "-"))
        .or_else(|| parse_symbol_as(state, "*)", "*"))
        .or_else(|| parse_symbol_as(state, "/)", "/"))
        .or_else(|| parse_symbol_as(state, "^)", "^"))
        .map(|parsed_symbol| GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: parsed_symbol,
        })
}

fn parse_gren_syntax_expose_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpose>> {
    if state.position.character == 0 {
        return None;
    }
    let start_position: lsp_types::Position = state.position;
    if parse_symbol(state, "(") {
        parse_gren_whitespace_and_comments(state);
        let maybe_operator_symbol: Option<GrenSyntaxNode<&str>> = parse_gren_operator_node(state);
        parse_gren_whitespace_and_comments(state);
        let _: bool = parse_symbol(state, ")");
        Some(GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: GrenSyntaxExpose::Operator(maybe_operator_symbol),
        })
    } else if let Some(variable_name) = parse_gren_lowercase_as_box_str(state) {
        Some(GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: GrenSyntaxExpose::Variable(variable_name),
        })
    } else if let Some(type_name_node) = parse_gren_uppercase_node(state) {
        parse_gren_whitespace_and_comments(state);
        if parse_symbol(state, "(") {
            parse_gren_whitespace_and_comments(state);
            let maybe_exposing_variants_range: Option<lsp_types::Range> =
                parse_symbol_as_range(state, "..");
            parse_gren_whitespace_and_comments(state);
            let _: bool = parse_symbol(state, ")");
            Some(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: start_position,
                    end: state.position,
                },
                value: GrenSyntaxExpose::ChoiceTypeIncludingVariants {
                    name: type_name_node,
                    open_range: maybe_exposing_variants_range,
                },
            })
        } else {
            Some(GrenSyntaxNode {
                range: type_name_node.range,
                value: GrenSyntaxExpose::Type(type_name_node.value),
            })
        }
    } else {
        None
    }
}

fn parse_gren_syntax_import_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxImport>> {
    let import_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "import")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_module_name_node: Option<GrenSyntaxNode<Box<str>>> =
        parse_gren_standalone_module_name_node(state);
    parse_gren_whitespace_and_comments(state);
    let maybe_as_keyword_range: Option<lsp_types::Range> = parse_gren_keyword_as_range(state, "as");
    parse_gren_whitespace_and_comments(state);
    let maybe_alias_name: Option<GrenSyntaxNode<Box<str>>> = parse_gren_uppercase_node(state);
    parse_gren_whitespace_and_comments(state);
    let maybe_exposing_keyword_range: Option<lsp_types::Range> =
        parse_gren_keyword_as_range(state, "exposing");
    parse_gren_whitespace_and_comments(state);
    let maybe_exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>> =
        parse_gren_syntax_exposing_node(state);
    let end_position: lsp_types::Position = maybe_exposing
        .as_ref()
        .map(|exposing| exposing.range.end)
        .or_else(|| maybe_exposing_keyword_range.map(|range| range.end))
        .or_else(|| maybe_alias_name.as_ref().map(|node| node.range.end))
        .or_else(|| maybe_as_keyword_range.map(|range| range.end))
        .or_else(|| maybe_module_name_node.as_ref().map(|node| node.range.end))
        .unwrap_or(import_keyword_range.end);
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: import_keyword_range.start,
            end: end_position,
        },
        value: GrenSyntaxImport {
            module_name: maybe_module_name_node,
            as_keyword_range: maybe_as_keyword_range,
            alias_name: maybe_alias_name,
            exposing_keyword_range: maybe_exposing_keyword_range,
            exposing: maybe_exposing,
        },
    })
}
fn parse_gren_syntax_exposing_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExposing>> {
    let start_position: lsp_types::Position = state.position;
    if !parse_symbol(state, "(") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    let exposing: GrenSyntaxExposing = match parse_symbol_as_range(state, "..") {
        Some(all_range) => {
            parse_gren_whitespace_and_comments(state);
            let _: bool = parse_symbol(state, ")");
            GrenSyntaxExposing::All(all_range)
        }
        None => {
            let mut expose_nodes: Vec<GrenSyntaxNode<GrenSyntaxExpose>> = Vec::new();
            while let Some(expose_node) = parse_gren_syntax_expose_node(state) {
                expose_nodes.push(expose_node);
                parse_gren_whitespace_and_comments(state);
                while parse_symbol(state, ",") {
                    parse_gren_whitespace_and_comments(state);
                }
            }
            let _: bool = parse_symbol(state, ")");
            GrenSyntaxExposing::Explicit(expose_nodes)
        }
    };
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: exposing,
    })
}

fn parse_gren_syntax_module_header(state: &mut ParseState) -> Option<GrenSyntaxModuleHeader> {
    if let Some(module_keyword_range) = parse_symbol_as_range(state, "module") {
        parse_gren_whitespace_and_comments(state);
        let maybe_module_name_node: Option<GrenSyntaxNode<Box<str>>> =
            parse_gren_standalone_module_name_node(state);
        parse_gren_whitespace_and_comments(state);
        let maybe_exposing_keyword_range: Option<lsp_types::Range> =
            parse_gren_keyword_as_range(state, "exposing");
        parse_gren_whitespace_and_comments(state);
        let maybe_exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>> =
            parse_gren_syntax_exposing_node(state);
        Some(GrenSyntaxModuleHeader {
            specific: GrenSyntaxModuleHeaderSpecific::Pure {
                module_keyword_range: module_keyword_range,
            },
            module_name: maybe_module_name_node,
            exposing_keyword_range: maybe_exposing_keyword_range,
            exposing: maybe_exposing,
        })
    } else if let Some(port_keyword_range) = parse_symbol_as_range(state, "port") {
        parse_gren_whitespace_and_comments(state);
        let module_keyword_range: lsp_types::Range = parse_symbol_as_range(state, "module")?;
        parse_gren_whitespace_and_comments(state);
        let maybe_module_name_node: Option<GrenSyntaxNode<Box<str>>> =
            parse_gren_standalone_module_name_node(state);
        parse_gren_whitespace_and_comments(state);
        let maybe_exposing_keyword_range: Option<lsp_types::Range> =
            parse_gren_keyword_as_range(state, "exposing");
        parse_gren_whitespace_and_comments(state);
        let maybe_exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>> =
            parse_gren_syntax_exposing_node(state);
        Some(GrenSyntaxModuleHeader {
            specific: GrenSyntaxModuleHeaderSpecific::Port {
                port_keyword_range: port_keyword_range,
                module_keyword_range: module_keyword_range,
            },
            module_name: maybe_module_name_node,
            exposing_keyword_range: maybe_exposing_keyword_range,
            exposing: maybe_exposing,
        })
    } else if let Some(effect_keyword_range) = parse_symbol_as_range(state, "effect") {
        parse_gren_whitespace_and_comments(state);
        let module_keyword_range: lsp_types::Range = parse_symbol_as_range(state, "module")?;
        parse_gren_whitespace_and_comments(state);
        let maybe_module_name_node: Option<GrenSyntaxNode<Box<str>>> =
            parse_gren_standalone_module_name_node(state);
        parse_gren_whitespace_and_comments(state);
        let where_keyword_range: lsp_types::Range = parse_symbol_as_range(state, "where")?;
        parse_gren_whitespace_and_comments(state);

        let maybe_command_entry: Option<EffectModuleHeaderEntry>;
        let maybe_subscription_entry: Option<EffectModuleHeaderEntry>;
        if parse_symbol(state, "{") {
            parse_gren_whitespace_and_comments(state);
            maybe_command_entry =
                parse_gren_syntax_effect_module_header_where_entry(state, "command");
            parse_gren_whitespace_and_comments(state);
            if parse_symbol(state, ",") {
                parse_gren_whitespace_and_comments(state);
            }
            maybe_subscription_entry =
                parse_gren_syntax_effect_module_header_where_entry(state, "subscription");
            parse_gren_whitespace_and_comments(state);
            let _: bool = parse_symbol(state, "}");
        } else {
            maybe_command_entry = None;
            maybe_subscription_entry = None;
        }

        parse_gren_whitespace_and_comments(state);
        let maybe_exposing_keyword_range: Option<lsp_types::Range> =
            parse_gren_keyword_as_range(state, "exposing");
        parse_gren_whitespace_and_comments(state);
        let maybe_exposing: Option<GrenSyntaxNode<GrenSyntaxExposing>> =
            parse_gren_syntax_exposing_node(state);
        Some(GrenSyntaxModuleHeader {
            specific: GrenSyntaxModuleHeaderSpecific::Effect {
                effect_keyword_range: effect_keyword_range,
                module_keyword_range,
                where_keyword_range: where_keyword_range,
                command: maybe_command_entry,
                subscription: maybe_subscription_entry,
            },
            module_name: maybe_module_name_node,
            exposing_keyword_range: maybe_exposing_keyword_range,
            exposing: maybe_exposing,
        })
    } else {
        None
    }
}

fn parse_gren_syntax_effect_module_header_where_entry(
    state: &mut ParseState,
    key: &'static str,
) -> Option<EffectModuleHeaderEntry> {
    let key_range: lsp_types::Range = parse_symbol_as_range(state, key)?;
    parse_gren_whitespace_and_comments(state);
    let equals_range: lsp_types::Range = parse_symbol_as_range(state, "=")?;
    parse_gren_whitespace_and_comments(state);
    let type_name_node: GrenSyntaxNode<Box<str>> = parse_gren_uppercase_node(state)?;
    Some(EffectModuleHeaderEntry {
        key_range: key_range,
        equals_range: equals_range,
        value_type_name: type_name_node,
    })
}
fn parse_gren_syntax_type_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxType>> {
    let start_type_node: GrenSyntaxNode<GrenSyntaxType> =
        parse_gren_syntax_type_not_function_node(state)?;
    parse_gren_whitespace_and_comments(state);
    if let Some(arrow_key_symbol_range) = parse_symbol_as_range(state, "->") {
        parse_gren_whitespace_and_comments(state);
        let maybe_output_type: Option<GrenSyntaxNode<GrenSyntaxType>> =
            if state.position.character > u32::from(state.indent) {
                parse_gren_syntax_type_space_separated_node(state)
            } else {
                None
            };
        Some(GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_type_node.range.start,
                end: match &maybe_output_type {
                    None => arrow_key_symbol_range.end,
                    Some(output_type_node) => output_type_node.range.end,
                },
            },
            value: GrenSyntaxType::Function {
                input: gren_syntax_node_box(start_type_node),
                arrow_key_symbol_range: arrow_key_symbol_range,
                output: maybe_output_type.map(gren_syntax_node_box),
            },
        })
    } else {
        Some(start_type_node)
    }
}
fn parse_gren_syntax_type_not_function_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxType>> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    parse_gren_syntax_type_construct_node(state).or_else(|| {
        let start_position: lsp_types::Position = state.position;
        parse_gren_lowercase_as_box_str(state)
            .map(GrenSyntaxType::Variable)
            .or_else(|| parse_gren_syntax_type_parenthesized(state))
            .or_else(|| parse_gren_syntax_type_record_or_record_extension(state))
            .map(|type_| GrenSyntaxNode {
                range: lsp_types::Range {
                    start: start_position,
                    end: state.position,
                },
                value: type_,
            })
    })
}
fn parse_gren_syntax_type_not_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxType>> {
    let start_position: lsp_types::Position = state.position;
    parse_gren_syntax_type_not_space_separated(state).map(|type_| GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: type_,
    })
}
fn parse_gren_syntax_type_not_space_separated(state: &mut ParseState) -> Option<GrenSyntaxType> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    parse_gren_lowercase_as_box_str(state)
        .map(GrenSyntaxType::Variable)
        .or_else(|| parse_gren_syntax_type_parenthesized(state))
        .or_else(|| {
            parse_gren_qualified_uppercase_reference_node(state).map(|reference_node| {
                GrenSyntaxType::Construct {
                    reference: reference_node,
                    arguments: vec![],
                }
            })
        })
        .or_else(|| parse_gren_syntax_type_record_or_record_extension(state))
}
fn parse_gren_syntax_type_record_or_record_extension(
    state: &mut ParseState,
) -> Option<GrenSyntaxType> {
    if state.source[state.offset_utf8..].starts_with("{-|") {
        return None;
    }
    if !parse_symbol(state, "{") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    while parse_symbol(state, ",") {
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_start_name: Option<GrenSyntaxNode<Box<str>>> = parse_gren_lowercase_as_node(state);
    parse_gren_whitespace_and_comments(state);
    if let Some(bar_key_symbol_range) = parse_symbol_as_range(state, "|") {
        parse_gren_whitespace_and_comments(state);
        let mut fields: Vec<GrenSyntaxTypeField> = Vec::new();
        while let Some(field) = parse_gren_syntax_type_field(state) {
            fields.push(field);
            parse_gren_whitespace_and_comments(state);
            while parse_symbol(state, ",") {
                parse_gren_whitespace_and_comments(state);
            }
        }
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxType::RecordExtension {
            record_variable: maybe_start_name,
            bar_key_symbol_range: bar_key_symbol_range,
            fields: fields,
        })
    } else if let Some(field0_name_node) = maybe_start_name {
        let maybe_field0_colon_key_symbol_range: Option<lsp_types::Range> =
            parse_symbol_as_range(state, ":");
        parse_gren_whitespace_and_comments(state);
        let maybe_field0_value: Option<GrenSyntaxNode<GrenSyntaxType>> =
            parse_gren_syntax_type_space_separated_node(state);
        parse_gren_whitespace_and_comments(state);
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
        let mut fields: Vec<GrenSyntaxTypeField> = vec![GrenSyntaxTypeField {
            name: field0_name_node,
            colon_key_symbol_range: maybe_field0_colon_key_symbol_range,
            value: maybe_field0_value,
        }];
        while let Some(field) = parse_gren_syntax_type_field(state) {
            fields.push(field);
            parse_gren_whitespace_and_comments(state);
            while parse_symbol(state, ",") {
                parse_gren_whitespace_and_comments(state);
            }
        }
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxType::Record(fields))
    } else {
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxType::Record(vec![]))
    }
}
fn parse_gren_syntax_type_field(state: &mut ParseState) -> Option<GrenSyntaxTypeField> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    let maybe_name: GrenSyntaxNode<Box<str>> = parse_gren_lowercase_as_node(state)?;
    parse_gren_whitespace_and_comments(state);
    let maybe_colon_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, ":");
    parse_gren_whitespace_and_comments(state);
    let maybe_value: Option<GrenSyntaxNode<GrenSyntaxType>> =
        parse_gren_syntax_type_space_separated_node(state);
    Some(GrenSyntaxTypeField {
        name: maybe_name,
        colon_key_symbol_range: maybe_colon_key_symbol_range,
        value: maybe_value,
    })
}
fn parse_gren_syntax_type_construct_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxType>> {
    let reference_node: GrenSyntaxNode<GrenQualifiedName> =
        parse_gren_qualified_uppercase_reference_node(state)?;
    parse_gren_whitespace_and_comments(state);
    let mut arguments: Vec<GrenSyntaxNode<GrenSyntaxType>> = Vec::new();
    let mut construct_end_position: lsp_types::Position = reference_node.range.end;
    while let Some(argument_node) = parse_gren_syntax_type_not_space_separated_node(state) {
        construct_end_position = argument_node.range.end;
        arguments.push(argument_node);
        parse_gren_whitespace_and_comments(state);
    }
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: reference_node.range.start,
            end: construct_end_position,
        },
        value: GrenSyntaxType::Construct {
            reference: reference_node,
            arguments: arguments,
        },
    })
}
fn parse_gren_qualified_uppercase_reference_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenQualifiedName>> {
    let start_position: lsp_types::Position = state.position;
    let start_offset_utf8: usize = state.offset_utf8;
    if !parse_same_line_char_if(state, char::is_uppercase) {
        return None;
    }
    parse_same_line_while(state, |c| c.is_alphanumeric() || c == '_');
    if parse_symbol(state, ".") {
        loop {
            let after_last_dot_offset_utf8: usize = state.offset_utf8;
            if parse_same_line_char_if(state, char::is_uppercase) {
                parse_same_line_while(state, |c| c.is_alphanumeric() || c == '_');
                if !parse_symbol(state, ".") {
                    return Some(GrenSyntaxNode {
                        range: lsp_types::Range {
                            start: start_position,
                            end: state.position,
                        },
                        value: GrenQualifiedName {
                            qualification: Box::from(
                                &state.source[start_offset_utf8..(after_last_dot_offset_utf8 - 1)],
                            ),
                            name: Box::from(
                                &state.source[after_last_dot_offset_utf8..state.offset_utf8],
                            ),
                        },
                    });
                }
            } else {
                // stopping at . and in effect having an empty name is explicitly allowed!
                return Some(GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: start_position,
                        end: state.position,
                    },
                    value: GrenQualifiedName {
                        qualification: Box::from(
                            &state.source[start_offset_utf8..(state.offset_utf8 - 1)],
                        ),
                        name: Box::from(""),
                    },
                });
            }
        }
    } else {
        Some(GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: GrenQualifiedName {
                qualification: Box::from(""),
                name: Box::from(&state.source[start_offset_utf8..state.offset_utf8]),
            },
        })
    }
}
fn parse_gren_syntax_type_parenthesized(state: &mut ParseState) -> Option<GrenSyntaxType> {
    if !parse_symbol(state, "(") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    let maybe_in_parens_0: Option<GrenSyntaxNode<GrenSyntaxType>> =
        parse_gren_syntax_type_space_separated_node(state);
    parse_gren_whitespace_and_comments(state);
    let _: bool = parse_symbol(state, ")");
    Some(GrenSyntaxType::Parenthesized(
        maybe_in_parens_0.map(gren_syntax_node_box),
    ))
}
fn parse_gren_syntax_pattern_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxPattern>> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    parse_gren_syntax_pattern_space_separated_node_starting_at_any_indent(state)
}
fn parse_gren_syntax_pattern_space_separated_node_starting_at_any_indent(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxPattern>> {
    let start_pattern: GrenSyntaxNode<GrenSyntaxPattern> =
        parse_gren_syntax_pattern_not_as_node(state)?;
    parse_gren_whitespace_and_comments(state);
    match parse_symbol_as_range(state, "as") {
        None => Some(start_pattern),
        Some(as_keyword_range) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_variable: Option<GrenSyntaxNode<Box<str>>> =
                parse_gren_lowercase_as_node(state);
            Some(GrenSyntaxNode {
                range: lsp_types::Range {
                    start: start_pattern.range.start,
                    end: match &maybe_variable {
                        Some(variable_node) => variable_node.range.end,
                        None => as_keyword_range.end,
                    },
                },
                value: GrenSyntaxPattern::As {
                    pattern: gren_syntax_node_box(start_pattern),
                    as_keyword_range: as_keyword_range,
                    variable: maybe_variable,
                },
            })
        }
    }
}

fn parse_gren_syntax_pattern_not_as_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxPattern>> {
    parse_gren_syntax_pattern_construct_node(state).or_else(|| {
        let start_position = state.position;
        parse_gren_syntax_pattern_ignored(state)
            .or_else(|| parse_gren_lowercase_as_box_str(state).map(GrenSyntaxPattern::Variable))
            .or_else(|| parse_gren_char(state).map(GrenSyntaxPattern::Char))
            .or_else(|| parse_gren_syntax_pattern_string(state))
            .or_else(|| parse_gren_syntax_pattern_parenthesized(state))
            .or_else(|| parse_gren_syntax_pattern_record(state))
            .or_else(|| parse_gren_syntax_pattern_integer(state))
            .map(|pattern| GrenSyntaxNode {
                range: lsp_types::Range {
                    start: start_position,
                    end: state.position,
                },
                value: pattern,
            })
    })
}
fn parse_gren_syntax_pattern_not_space_separated(
    state: &mut ParseState,
) -> Option<GrenSyntaxPattern> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    parse_gren_syntax_pattern_ignored(state)
        .or_else(|| parse_gren_syntax_pattern_parenthesized(state))
        .or_else(|| parse_gren_lowercase_as_box_str(state).map(GrenSyntaxPattern::Variable))
        .or_else(|| {
            parse_gren_qualified_uppercase_reference_node(state).map(|reference_node| {
                GrenSyntaxPattern::Variant {
                    reference: reference_node,
                    value: None,
                }
            })
        })
        .or_else(|| parse_gren_char(state).map(GrenSyntaxPattern::Char))
        .or_else(|| parse_gren_syntax_pattern_string(state))
        .or_else(|| parse_gren_syntax_pattern_record(state))
        .or_else(|| parse_gren_syntax_pattern_integer(state))
}
fn parse_gren_syntax_pattern_ignored(state: &mut ParseState) -> Option<GrenSyntaxPattern> {
    if !parse_symbol(state, "_") {
        return None;
    }
    Some(GrenSyntaxPattern::Ignored(parse_gren_lowercase_as_box_str(
        state,
    )))
}
fn parse_gren_syntax_pattern_record(state: &mut ParseState) -> Option<GrenSyntaxPattern> {
    if state.source[state.offset_utf8..].starts_with("{-|") {
        return None;
    }
    if !parse_symbol(state, "{") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    while parse_symbol(state, ",") {
        parse_gren_whitespace_and_comments(state);
    }
    let mut fields: Vec<GrenSyntaxPatternField> = Vec::new();
    while let Some(field) = parse_gren_syntax_pattern_field(state) {
        fields.push(field);
        parse_gren_whitespace_and_comments(state);
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
    }
    let _: bool = parse_symbol(state, "}");
    Some(GrenSyntaxPattern::Record(fields))
}
fn parse_gren_syntax_pattern_field(state: &mut ParseState) -> Option<GrenSyntaxPatternField> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    let Some(field_name_node) = parse_gren_lowercase_as_node(state) else {
        return None;
    };
    parse_gren_whitespace_and_comments(state);
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    let maybe_value: Option<GrenSyntaxNode<GrenSyntaxPattern>> =
        parse_gren_syntax_pattern_space_separated_node(state);
    Some(GrenSyntaxPatternField {
        name: field_name_node,
        equals_key_symbol_range: maybe_equals_key_symbol_range,
        value: maybe_value,
    })
}
fn parse_gren_syntax_pattern_not_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxPattern>> {
    let start_position: lsp_types::Position = state.position;
    parse_gren_syntax_pattern_not_space_separated(state).map(|pattern| GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: pattern,
    })
}

fn parse_gren_syntax_pattern_construct_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxPattern>> {
    let reference_node: GrenSyntaxNode<GrenQualifiedName> =
        parse_gren_qualified_uppercase_reference_node(state)?;
    parse_gren_whitespace_and_comments(state);
    let maybe_value = parse_gren_syntax_pattern_not_space_separated_node(state);
    let variant_end_position: lsp_types::Position = maybe_value
        .as_ref()
        .map(|value_node| value_node.range.end)
        .unwrap_or(reference_node.range.end);
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: reference_node.range.start,
            end: variant_end_position,
        },
        value: GrenSyntaxPattern::Variant {
            reference: reference_node,
            value: maybe_value.map(gren_syntax_node_box),
        },
    })
}
fn parse_gren_syntax_pattern_string(state: &mut ParseState) -> Option<GrenSyntaxPattern> {
    parse_gren_string_triple_quoted(state)
        .map(|content| GrenSyntaxPattern::String {
            content: content,
            quoting_style: GrenSyntaxStringQuotingStyle::TripleQuoted,
        })
        .or_else(|| {
            parse_gren_string_single_quoted(state).map(|content| GrenSyntaxPattern::String {
                content: content,
                quoting_style: GrenSyntaxStringQuotingStyle::SingleQuoted,
            })
        })
}

fn parse_gren_syntax_pattern_integer(state: &mut ParseState) -> Option<GrenSyntaxPattern> {
    parse_gren_unsigned_integer_base10_as_i64(state)
        .map(|value| GrenSyntaxPattern::Int {
            base: GrenSyntaxIntBase::IntBase10,
            value: value,
        })
        .or_else(|| {
            parse_gren_unsigned_integer_base16_as_i64(state).map(|value| GrenSyntaxPattern::Int {
                base: GrenSyntaxIntBase::IntBase16,
                value: value,
            })
        })
}
fn parse_gren_syntax_pattern_parenthesized(state: &mut ParseState) -> Option<GrenSyntaxPattern> {
    if !parse_symbol(state, "(") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    let maybe_in_parens_0: Option<GrenSyntaxNode<GrenSyntaxPattern>> =
        parse_gren_syntax_pattern_space_separated_node(state);
    parse_gren_whitespace_and_comments(state);
    let _: bool = parse_symbol(state, ")");
    Some(GrenSyntaxPattern::Parenthesized(
        maybe_in_parens_0.map(gren_syntax_node_box),
    ))
}
fn parse_gren_unsigned_integer_base16_as_i64(
    state: &mut ParseState,
) -> Option<Result<i64, Box<str>>> {
    if !parse_symbol(state, "0x") {
        return None;
    }
    let hex_str: &str = parse_same_line_while_as_str(state, |c| c.is_ascii_hexdigit());
    Some(i64::from_str_radix(hex_str, 16).map_err(|_| Box::from(hex_str)))
}
fn parse_gren_unsigned_integer_base10_as_i64(
    state: &mut ParseState,
) -> Option<Result<i64, Box<str>>> {
    let start_offset_utf8: usize = state.offset_utf8;
    if parse_unsigned_integer_base10(state) {
        let decimal_str: &str = &state.source[start_offset_utf8..state.offset_utf8];
        Some(str::parse::<i64>(decimal_str).map_err(|_| Box::from(decimal_str)))
    } else {
        None
    }
}
fn parse_gren_syntax_expression_number(state: &mut ParseState) -> Option<GrenSyntaxExpression> {
    if let Some(unsigned_int_base16) = parse_gren_unsigned_integer_base16_as_i64(state) {
        return Some(GrenSyntaxExpression::Integer {
            base: GrenSyntaxIntBase::IntBase16,
            value: unsigned_int_base16,
        });
    }
    let start_offset_utf8: usize = state.offset_utf8;
    if !parse_unsigned_integer_base10(state) {
        return None;
    }
    let has_decimal_point: bool = parse_symbol(state, ".");
    if has_decimal_point {
        parse_same_line_while(state, |c| c.is_ascii_digit());
    }
    let has_exponent_plus: Option<bool> =
        if parse_same_line_char_if(state, |c| c == 'e' || c == 'E') {
            if parse_symbol(state, "+") {
                let _: bool = parse_unsigned_integer_base10(state);
                Some(true)
            } else {
                let _: bool = parse_symbol(state, "-");
                let _: bool = parse_unsigned_integer_base10(state);
                Some(false)
            }
        } else {
            None
        };
    let full_chomped_str: &str = &state.source[start_offset_utf8..state.offset_utf8];
    Some(if has_decimal_point || has_exponent_plus.is_some() {
        GrenSyntaxExpression::Float(
            if has_exponent_plus.is_some_and(|exponent_is_plus| exponent_is_plus) {
                str::parse::<f64>(&full_chomped_str.replace("+", ""))
                    .map_err(|_| Box::from(full_chomped_str))
            } else {
                str::parse::<f64>(full_chomped_str).map_err(|_| Box::from(full_chomped_str))
            },
        )
    } else {
        GrenSyntaxExpression::Integer {
            base: GrenSyntaxIntBase::IntBase10,
            value: str::parse::<i64>(full_chomped_str).map_err(|_| Box::from(full_chomped_str)),
        }
    })
}
fn parse_gren_char(state: &mut ParseState) -> Option<Option<char>> {
    if !parse_symbol(state, "'") {
        return None;
    }
    let result: Option<char> = parse_gren_text_content_char(state);
    let _: bool = parse_symbol(state, "'");
    Some(result)
}
/// commits after a single quote, so check for triple quoted beforehand
fn parse_gren_string_single_quoted(state: &mut ParseState) -> Option<String> {
    if !parse_symbol(state, "\"") {
        return None;
    }
    let mut result: String = String::new();
    while !(parse_symbol(state, "\"")
        || str_starts_with_linebreak(&state.source[state.offset_utf8..]))
    {
        match parse_gren_text_content_char(state) {
            Some(next_content_char) => {
                result.push(next_content_char);
            }
            None => match parse_any_guaranteed_non_linebreak_char_as_char(state) {
                Some(next_content_char) => {
                    result.push(next_content_char);
                }
                None => return Some(result),
            },
        }
    }
    Some(result)
}
fn parse_gren_string_triple_quoted(state: &mut ParseState) -> Option<String> {
    if !parse_symbol(state, "\"\"\"") {
        return None;
    }
    let mut result: String = String::new();
    while !parse_symbol(state, "\"\"\"") {
        match parse_linebreak_as_str(state) {
            Some(linebreak) => result.push_str(linebreak),
            None => match parse_char_symbol_as_char(state, '\"')
                .or_else(|| parse_gren_text_content_char(state))
            {
                Some(next_content_char) => {
                    result.push(next_content_char);
                }
                None => match parse_any_guaranteed_non_linebreak_char_as_char(state) {
                    Some(next_content_char) => {
                        result.push(next_content_char);
                    }
                    None => return Some(result),
                },
            },
        }
    }
    Some(result)
}
fn parse_gren_text_content_char(state: &mut ParseState) -> Option<char> {
    parse_symbol_as(state, "\\\\", '\\')
        .or_else(|| parse_symbol_as(state, "\\'", '\''))
        .or_else(|| parse_symbol_as(state, "\\\n", '\n'))
        .or_else(|| parse_symbol_as(state, "\\\r", '\r'))
        .or_else(|| parse_symbol_as(state, "\\\t", '\t'))
        .or_else(|| parse_symbol_as(state, "\\\"", '"'))
        .or_else(|| {
            let start_offset_utf8: usize = state.offset_utf8;
            let start_position: lsp_types::Position = state.position;
            let reset_parse_state = |progressed_state: &mut ParseState| {
                progressed_state.offset_utf8 = start_offset_utf8;
                progressed_state.position = start_position;
            };
            if !parse_symbol(state, "\\u{") {
                return None;
            }
            let unicode_hex_start_offset_utf8: usize = state.offset_utf8;
            parse_same_line_while(state, |c| c.is_ascii_hexdigit());
            let unicode_hex_str: &str =
                &state.source[unicode_hex_start_offset_utf8..state.offset_utf8];
            let _: bool = parse_symbol(state, "}");
            let Ok(first_utf16_code) = u16::from_str_radix(unicode_hex_str, 16) else {
                reset_parse_state(state);
                return None;
            };
            match char::from_u32(u32::from(first_utf16_code)) {
                Some(char) => Some(char),
                None => {
                    if !parse_symbol(state, "\\u{") {
                        reset_parse_state(state);
                        return None;
                    }
                    let second_unicode_hex_start_offset_utf8: usize = state.offset_utf8;
                    parse_same_line_while(state, |c| c.is_ascii_hexdigit());
                    let second_unicode_hex_str: &str =
                        &state.source[second_unicode_hex_start_offset_utf8..state.offset_utf8];
                    let _: bool = parse_symbol(state, "}");
                    let Ok(second_utf16_code) = u16::from_str_radix(second_unicode_hex_str, 16)
                    else {
                        reset_parse_state(state);
                        return None;
                    };
                    char::decode_utf16([first_utf16_code, second_utf16_code])
                        .find_map(Result::ok)
                        .or_else(|| {
                            reset_parse_state(state);
                            None
                        })
                }
            }
        })
        .or_else(|| {
            if str_starts_with_linebreak(&state.source[state.offset_utf8..]) {
                None
            } else {
                match state.source[state.offset_utf8..].chars().next() {
                    None => None,
                    Some(plain_char) => {
                        state.offset_utf8 += plain_char.len_utf8();
                        state.position.character += plain_char.len_utf16() as u32;
                        Some(plain_char)
                    }
                }
            }
        })
}

fn parse_gren_syntax_expression_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    parse_gren_syntax_expression_if_then_else(state)
        .or_else(|| parse_gren_syntax_expression_case_of(state))
        .or_else(|| parse_gren_syntax_expression_let_in(state))
        .or_else(|| parse_gren_syntax_expression_lambda(state))
        .or_else(|| {
            let left_node: GrenSyntaxNode<GrenSyntaxExpression> =
                parse_gren_syntax_expression_call_or_not_space_separated_node(state)?;
            parse_gren_whitespace_and_comments(state);
            Some(match parse_gren_operator_node(state) {
                None => left_node,
                Some(operator_node) => {
                    parse_gren_whitespace_and_comments(state);
                    let maybe_right: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
                        parse_gren_syntax_expression_space_separated_node(state);
                    GrenSyntaxNode {
                        range: lsp_types::Range {
                            start: left_node.range.start,
                            end: match &maybe_right {
                                None => operator_node.range.end,
                                Some(right_node) => right_node.range.end,
                            },
                        },
                        value: GrenSyntaxExpression::InfixOperationIgnoringPrecedence {
                            left: gren_syntax_node_box(left_node),
                            operator: operator_node,
                            right: maybe_right.map(gren_syntax_node_box),
                        },
                    }
                }
            })
        })
}
fn parse_gren_syntax_expression_call_or_not_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let called_node: GrenSyntaxNode<GrenSyntaxExpression> =
        parse_gren_syntax_expression_not_space_separated_node(state)?;
    parse_gren_whitespace_and_comments(state);
    Some(
        if (state.position.character > u32::from(state.indent))
            && let Some(argument0_node) =
                parse_gren_syntax_expression_not_space_separated_node(state)
        {
            let mut argument1_up: Vec<GrenSyntaxNode<GrenSyntaxExpression>> = Vec::new();
            let mut call_end_position: lsp_types::Position = argument0_node.range.end;
            'parsing_argument1_up: loop {
                parse_gren_whitespace_and_comments(state);
                if state.position.character <= u32::from(state.indent) {
                    break 'parsing_argument1_up;
                }
                match parse_gren_syntax_expression_not_space_separated_node(state) {
                    None => {
                        break 'parsing_argument1_up;
                    }
                    Some(argument_node) => {
                        call_end_position = argument_node.range.end;
                        argument1_up.push(argument_node);
                    }
                }
            }
            GrenSyntaxNode {
                range: lsp_types::Range {
                    start: called_node.range.start,
                    end: call_end_position,
                },
                value: GrenSyntaxExpression::Call {
                    called: gren_syntax_node_box(called_node),
                    argument0: gren_syntax_node_box(argument0_node),
                    argument1_up: argument1_up,
                },
            }
        } else {
            called_node
        },
    )
}
fn parse_gren_syntax_expression_not_space_separated_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let start_position: lsp_types::Position = state.position;
    let start_expression: GrenSyntaxExpression = parse_gren_syntax_expression_string(state)
        .or_else(|| parse_gren_syntax_expression_list(state))
        .or_else(|| parse_gren_syntax_expression_operator_function_or_parenthesized(state))
        .or_else(|| parse_gren_syntax_expression_record_access_function(state))
        .or_else(|| parse_gren_syntax_expression_reference(state))
        .or_else(|| parse_gren_syntax_expression_record_or_record_update(state))
        .or_else(|| parse_gren_syntax_expression_number(state))
        .or_else(|| parse_gren_char(state).map(GrenSyntaxExpression::Char))
        .or_else(|| parse_gren_syntax_expression_negation(state))?;
    let mut result_node: GrenSyntaxNode<GrenSyntaxExpression> = GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: state.position,
        },
        value: start_expression,
    };
    while parse_symbol(state, ".") {
        let maybe_field_name: Option<GrenSyntaxNode<Box<str>>> =
            parse_gren_lowercase_as_node(state);
        result_node = GrenSyntaxNode {
            range: lsp_types::Range {
                start: start_position,
                end: state.position,
            },
            value: GrenSyntaxExpression::RecordAccess {
                record: gren_syntax_node_box(result_node),
                field: maybe_field_name,
            },
        }
    }
    Some(result_node)
}
fn parse_gren_syntax_expression_record_access_function(
    state: &mut ParseState,
) -> Option<GrenSyntaxExpression> {
    if !parse_symbol(state, ".") {
        return None;
    }
    Some(GrenSyntaxExpression::RecordAccessFunction(
        parse_gren_lowercase_as_node(state),
    ))
}
fn parse_gren_syntax_expression_negation(state: &mut ParseState) -> Option<GrenSyntaxExpression> {
    if state.source[state.offset_utf8..]
        .chars()
        .nth(1)
        .is_some_and(char::is_whitespace)
    {
        // exit if - is followed by whitespace, as that means it is a subtraction operation instead
        return None;
    }
    if !parse_symbol(state, "-") {
        return None;
    }
    Some(GrenSyntaxExpression::Negation(
        parse_gren_syntax_expression_not_space_separated_node(state).map(gren_syntax_node_box),
    ))
}
fn str_starts_with_keyword(source: &str, keyword: &'static str) -> bool {
    source.starts_with(keyword)
        && source
            .chars()
            .skip(keyword.len())
            .next()
            .is_some_and(|c| c != '_' && !c.is_alphanumeric())
}
fn parse_gren_syntax_expression_reference(state: &mut ParseState) -> Option<GrenSyntaxExpression> {
    // can be optimized by e.g. adding a non-state-mutating parse_gren_lowercase_as_string
    // that checks for keywords on successful chomp and returns None only then (and if no keyword, mutate the state)
    if str_starts_with_keyword(&state.source[state.offset_utf8..], "in")
        || str_starts_with_keyword(&state.source[state.offset_utf8..], "is")
        || str_starts_with_keyword(&state.source[state.offset_utf8..], "then")
        || str_starts_with_keyword(&state.source[state.offset_utf8..], "else")
    {
        return None;
    }
    parse_gren_lowercase_as_box_str(state)
        .map(|name| GrenSyntaxExpression::Reference {
            qualification: Box::from(""),
            name: name,
        })
        .or_else(|| {
            let start_offset_utf8: usize = state.offset_utf8;
            if !parse_same_line_char_if(state, char::is_uppercase) {
                return None;
            }
            parse_same_line_while(state, |c| c.is_alphanumeric() || c == '_');
            if parse_symbol(state, ".") {
                loop {
                    let after_last_dot_offset_utf8: usize = state.offset_utf8;
                    if let Some(name) = parse_gren_lowercase_as_box_str(state) {
                        return Some(GrenSyntaxExpression::Reference {
                            qualification: Box::from(
                                &state.source[start_offset_utf8..(after_last_dot_offset_utf8 - 1)],
                            ),
                            name: name,
                        });
                    } else if parse_same_line_char_if(state, char::is_uppercase) {
                        parse_same_line_while(state, |c| c.is_alphanumeric() || c == '_');
                        if !parse_symbol(state, ".") {
                            return Some(GrenSyntaxExpression::Reference {
                                qualification: Box::from(
                                    &state.source
                                        [start_offset_utf8..(after_last_dot_offset_utf8 - 1)],
                                ),
                                name: Box::from(
                                    &state.source[after_last_dot_offset_utf8..state.offset_utf8],
                                ),
                            });
                        }
                    } else {
                        // stopping at . and in effect having an empty name is explicitly allowed!
                        return Some(GrenSyntaxExpression::Reference {
                            qualification: Box::from(
                                &state.source[start_offset_utf8..(state.offset_utf8 - 1)],
                            ),
                            name: Box::from(""),
                        });
                    }
                }
            } else {
                Some(GrenSyntaxExpression::Reference {
                    qualification: Box::from(""),
                    name: Box::from(&state.source[start_offset_utf8..state.offset_utf8]),
                })
            }
        })
}
fn parse_gren_syntax_expression_record_or_record_update(
    state: &mut ParseState,
) -> Option<GrenSyntaxExpression> {
    if state.source[state.offset_utf8..].starts_with("{-|") {
        return None;
    }
    if !parse_symbol(state, "{") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    while parse_symbol(state, ",") {
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_start_name: Option<GrenSyntaxNode<Box<str>>> = parse_gren_lowercase_as_node(state);
    parse_gren_whitespace_and_comments(state);
    if let Some(bar_key_symbol_range) = parse_symbol_as_range(state, "|") {
        parse_gren_whitespace_and_comments(state);
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
        let mut fields: Vec<GrenSyntaxExpressionField> = Vec::new();
        while let Some(field) = parse_gren_syntax_expression_field(state) {
            fields.push(field);
            parse_gren_whitespace_and_comments(state);
            while parse_symbol(state, ",") {
                parse_gren_whitespace_and_comments(state);
            }
        }
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxExpression::RecordUpdate {
            record_variable: maybe_start_name,
            bar_key_symbol_range: bar_key_symbol_range,
            fields: fields,
        })
    } else if let Some(field0_name_node) = maybe_start_name {
        let maybe_field0_equals_key_symbol_range: Option<lsp_types::Range> =
            parse_symbol_as_range(state, "=");
        parse_gren_whitespace_and_comments(state);
        let maybe_field0_value: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
            parse_gren_syntax_expression_space_separated_node(state);
        parse_gren_whitespace_and_comments(state);
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
        let mut fields: Vec<GrenSyntaxExpressionField> = vec![GrenSyntaxExpressionField {
            name: field0_name_node,
            equals_key_symbol_range: maybe_field0_equals_key_symbol_range,
            value: maybe_field0_value,
        }];
        while let Some(field) = parse_gren_syntax_expression_field(state) {
            fields.push(field);
            parse_gren_whitespace_and_comments(state);
            while parse_symbol(state, ",") {
                parse_gren_whitespace_and_comments(state);
            }
        }
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxExpression::Record(fields))
    } else {
        let _: bool = parse_symbol(state, "}");
        Some(GrenSyntaxExpression::Record(vec![]))
    }
}
fn parse_gren_syntax_expression_field(state: &mut ParseState) -> Option<GrenSyntaxExpressionField> {
    if state.position.character <= u32::from(state.indent) {
        return None;
    }
    let name_node: GrenSyntaxNode<Box<str>> = parse_gren_lowercase_as_node(state)?;
    parse_gren_whitespace_and_comments(state);
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    let maybe_value: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        parse_gren_syntax_expression_space_separated_node(state);
    Some(GrenSyntaxExpressionField {
        name: name_node,
        equals_key_symbol_range: maybe_equals_key_symbol_range,
        value: maybe_value,
    })
}
fn parse_gren_syntax_expression_if_then_else(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let if_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "if")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_condition: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        parse_gren_syntax_expression_space_separated_node(state);
    parse_gren_whitespace_and_comments(state);
    Some(
        if let Some(then_keyword_range) = parse_symbol_as_range(state, "then") {
            parse_gren_whitespace_and_comments(state);
            let maybe_on_true: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
                parse_gren_syntax_expression_space_separated_node(state);
            parse_gren_whitespace_and_comments(state);
            if let Some(else_keyword_range) = parse_symbol_as_range(state, "else") {
                parse_gren_whitespace_and_comments(state);
                let maybe_on_false: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
                    parse_gren_syntax_expression_space_separated_node(state);
                GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: if_keyword_range.start,
                        end: match &maybe_on_false {
                            None => else_keyword_range.end,
                            Some(on_false_node) => on_false_node.range.end,
                        },
                    },
                    value: GrenSyntaxExpression::IfThenElse {
                        condition: maybe_condition.map(gren_syntax_node_box),
                        then_keyword_range: Some(then_keyword_range),
                        on_true: maybe_on_true.map(gren_syntax_node_box),
                        else_keyword_range: Some(else_keyword_range),
                        on_false: maybe_on_false.map(gren_syntax_node_box),
                    },
                }
            } else {
                GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: if_keyword_range.start,
                        end: match &maybe_on_true {
                            None => then_keyword_range.end,
                            Some(on_true_node) => on_true_node.range.end,
                        },
                    },
                    value: GrenSyntaxExpression::IfThenElse {
                        condition: maybe_condition.map(gren_syntax_node_box),
                        then_keyword_range: Some(then_keyword_range),
                        on_true: maybe_on_true.map(gren_syntax_node_box),
                        else_keyword_range: None,
                        on_false: None,
                    },
                }
            }
        } else {
            GrenSyntaxNode {
                range: lsp_types::Range {
                    start: if_keyword_range.start,
                    end: match &maybe_condition {
                        None => if_keyword_range.end,
                        Some(condition_node) => condition_node.range.end,
                    },
                },
                value: GrenSyntaxExpression::IfThenElse {
                    condition: maybe_condition.map(gren_syntax_node_box),
                    then_keyword_range: None,
                    on_true: None,
                    else_keyword_range: None,
                    on_false: None,
                },
            }
        },
    )
}
fn parse_gren_syntax_expression_lambda(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let backslash_key_symbol_range: lsp_types::Range = parse_symbol_as_range(state, "\\")?;
    let mut syntax_before_result_end_position: lsp_types::Position = backslash_key_symbol_range.end;
    parse_gren_whitespace_and_comments(state);
    let mut parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>> = Vec::new();
    while let Some(parameter_node) = parse_gren_syntax_pattern_not_space_separated_node(state) {
        syntax_before_result_end_position = parameter_node.range.end;
        parameters.push(parameter_node);
        parse_gren_whitespace_and_comments(state);
        // be lenient in allowing , after lambda parameters, even though it's invalid syntax
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
    }
    let maybe_arrow_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "->");
    parse_gren_whitespace_and_comments(state);
    let maybe_result: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        if state.position.character > u32::from(state.indent) {
            parse_gren_syntax_expression_space_separated_node(state)
        } else {
            None
        };
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: backslash_key_symbol_range.start,
            end: match &maybe_result {
                None => syntax_before_result_end_position,
                Some(result_node) => result_node.range.end,
            },
        },
        value: GrenSyntaxExpression::Lambda {
            parameters: parameters,
            arrow_key_symbol_range: maybe_arrow_key_symbol_range,
            result: maybe_result.map(gren_syntax_node_box),
        },
    })
}
fn parse_gren_syntax_expression_case_of(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let case_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "when")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_matched: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        parse_gren_syntax_expression_space_separated_node(state);
    parse_gren_whitespace_and_comments(state);
    Some(match parse_symbol_as_range(state, "is") {
        None => GrenSyntaxNode {
            range: lsp_types::Range {
                start: case_keyword_range.start,
                end: match &maybe_matched {
                    None => case_keyword_range.end,
                    Some(matched_node) => matched_node.range.end,
                },
            },
            value: GrenSyntaxExpression::CaseOf {
                matched: maybe_matched.map(gren_syntax_node_box),
                of_keyword_range: None,
                cases: vec![],
            },
        },
        Some(of_keyword_range) => {
            parse_gren_whitespace_and_comments(state);
            if state.position.character <= u32::from(state.indent) {
                GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: case_keyword_range.start,
                        end: of_keyword_range.end,
                    },
                    value: GrenSyntaxExpression::CaseOf {
                        matched: maybe_matched.map(gren_syntax_node_box),
                        of_keyword_range: Some(of_keyword_range),
                        cases: vec![],
                    },
                }
            } else {
                parse_state_push_indent(state, state.position.character as u16);
                let mut full_end_position: lsp_types::Position = of_keyword_range.end;
                let mut cases: Vec<GrenSyntaxExpressionCase> = Vec::new();
                while let Some(case) = parse_gren_syntax_expression_case(state) {
                    full_end_position = case
                        .result
                        .as_ref()
                        .map(|result| result.range.end)
                        .or_else(|| case.arrow_key_symbol_range.as_ref().map(|range| range.end))
                        .unwrap_or(case.pattern.range.end);
                    cases.push(case);
                    parse_gren_whitespace_and_comments(state);
                }
                parse_state_pop_indent(state);
                GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: case_keyword_range.start,
                        end: full_end_position,
                    },
                    value: GrenSyntaxExpression::CaseOf {
                        matched: maybe_matched.map(gren_syntax_node_box),
                        of_keyword_range: Some(of_keyword_range),
                        cases,
                    },
                }
            }
        }
    })
}
fn parse_gren_syntax_expression_case(state: &mut ParseState) -> Option<GrenSyntaxExpressionCase> {
    if state.position.character < u32::from(state.indent) {
        return None;
    }
    let case_pattern_node: GrenSyntaxNode<GrenSyntaxPattern> =
        parse_gren_syntax_pattern_space_separated_node_starting_at_any_indent(state)?;
    parse_gren_whitespace_and_comments(state);
    Some(match parse_symbol_as_range(state, "->") {
        None => GrenSyntaxExpressionCase {
            pattern: case_pattern_node,
            arrow_key_symbol_range: None,
            result: None,
        },
        Some(arrow_key_symbol_range) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_result = parse_gren_syntax_expression_space_separated_node(state);
            GrenSyntaxExpressionCase {
                pattern: case_pattern_node,
                arrow_key_symbol_range: Some(arrow_key_symbol_range),
                result: maybe_result,
            }
        }
    })
}

fn parse_gren_syntax_expression_let_in(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxExpression>> {
    let let_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "let")?;
    parse_gren_whitespace_and_comments(state);
    Some(if state.position.character <= u32::from(state.indent) {
        GrenSyntaxNode {
            range: let_keyword_range,
            value: GrenSyntaxExpression::LetIn {
                declarations: vec![],
                in_keyword_range: None,
                result: None,
            },
        }
    } else {
        parse_state_push_indent(state, state.position.character as u16);
        let mut syntax_before_in_key_symbol_end_position: lsp_types::Position =
            let_keyword_range.end;
        let mut declarations: Vec<GrenSyntaxNode<GrenSyntaxLetDeclaration>> = Vec::new();
        let maybe_in_keyword_range: Option<lsp_types::Range> = 'parsing_declarations: loop {
            if let Some(in_keyword_range) = parse_gren_keyword_as_range(state, "in") {
                break 'parsing_declarations Some(in_keyword_range);
            }
            match parse_gren_syntax_let_declaration(state) {
                None => {
                    break 'parsing_declarations None;
                }
                Some(declaration_node) => {
                    syntax_before_in_key_symbol_end_position = declaration_node.range.end;
                    declarations.push(declaration_node);
                    parse_gren_whitespace_and_comments(state);
                }
            }
        };
        parse_state_pop_indent(state);
        parse_gren_whitespace_and_comments(state);
        let maybe_result: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
            parse_gren_syntax_expression_space_separated_node(state);
        GrenSyntaxNode {
            range: lsp_types::Range {
                start: let_keyword_range.start,
                end: match &maybe_result {
                    None => maybe_in_keyword_range
                        .map(|range| range.end)
                        .unwrap_or(syntax_before_in_key_symbol_end_position),
                    Some(result_node) => result_node.range.end,
                },
            },
            value: GrenSyntaxExpression::LetIn {
                declarations: declarations,
                in_keyword_range: maybe_in_keyword_range,
                result: maybe_result.map(gren_syntax_node_box),
            },
        }
    })
}
fn parse_gren_syntax_let_declaration(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxLetDeclaration>> {
    if state.position.character < u32::from(state.indent) {
        return None;
    }
    parse_gren_syntax_let_variable_declaration_node(state)
        .or_else(|| parse_gren_syntax_let_destructuring_node(state))
}
fn parse_gren_syntax_let_destructuring_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxLetDeclaration>> {
    let pattern_node: GrenSyntaxNode<GrenSyntaxPattern> =
        parse_gren_syntax_pattern_space_separated_node_starting_at_any_indent(state)?;
    parse_gren_whitespace_and_comments(state);
    Some(match parse_symbol_as_range(state, "=") {
        None => GrenSyntaxNode {
            range: pattern_node.range,
            value: GrenSyntaxLetDeclaration::Destructuring {
                pattern: pattern_node,
                equals_key_symbol_range: None,
                expression: None,
            },
        },
        Some(equals_key_symbol_range) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_expression: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
                parse_gren_syntax_expression_space_separated_node(state);
            GrenSyntaxNode {
                range: lsp_types::Range {
                    start: pattern_node.range.start,
                    end: match &maybe_expression {
                        None => equals_key_symbol_range.end,
                        Some(expression_node) => expression_node.range.end,
                    },
                },
                value: GrenSyntaxLetDeclaration::Destructuring {
                    pattern: pattern_node,
                    equals_key_symbol_range: Some(equals_key_symbol_range),
                    expression: maybe_expression,
                },
            }
        }
    })
}
fn parse_gren_syntax_let_variable_declaration_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxLetDeclaration>> {
    let start_name_node: GrenSyntaxNode<Box<str>> = parse_gren_lowercase_as_node(state)?;
    parse_gren_whitespace_and_comments(state);
    Some(match parse_symbol_as_range(state, ":") {
        None => parse_gren_syntax_let_variable_declaration_node_after_maybe_signature_and_name(
            state,
            start_name_node,
            None,
        ),
        Some(colon_key_symbol_range) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_type: Option<GrenSyntaxNode<GrenSyntaxType>> =
                parse_gren_syntax_type_space_separated_node(state);
            parse_gren_whitespace_and_comments(state);
            match parse_symbol_as_range(state, &start_name_node.value) {
                None => GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: start_name_node.range.start,
                        end: maybe_type
                            .as_ref()
                            .map(|node| node.range.end)
                            .unwrap_or_else(|| colon_key_symbol_range.end),
                    },
                    value: GrenSyntaxLetDeclaration::VariableDeclaration {
                        start_name: start_name_node,
                        signature: Some(GrenSyntaxVariableDeclarationSignature {
                            colon_key_symbol_range: colon_key_symbol_range,
                            type_: maybe_type,
                            implementation_name_range: None,
                        }),
                        parameters: vec![],
                        equals_key_symbol_range: None,
                        result: None,
                    },
                },
                Some(implementation_name_range) => {
                    parse_gren_whitespace_and_comments(state);
                    parse_gren_syntax_let_variable_declaration_node_after_maybe_signature_and_name(
                        state,
                        start_name_node,
                        Some(GrenSyntaxVariableDeclarationSignature {
                            colon_key_symbol_range: colon_key_symbol_range,
                            type_: maybe_type,
                            implementation_name_range: Some(implementation_name_range),
                        }),
                    )
                }
            }
        }
    })
}
fn parse_gren_syntax_let_variable_declaration_node_after_maybe_signature_and_name(
    state: &mut ParseState,
    start_name_node: GrenSyntaxNode<Box<str>>,
    maybe_signature: Option<GrenSyntaxVariableDeclarationSignature>,
) -> GrenSyntaxNode<GrenSyntaxLetDeclaration> {
    let mut syntax_before_equals_key_symbol_end_location: lsp_types::Position =
        match &maybe_signature {
            Some(signature) => signature
                .implementation_name_range
                .map(|range| range.end)
                .or_else(|| signature.type_.as_ref().map(|node| node.range.end))
                .unwrap_or(signature.colon_key_symbol_range.end),
            None => start_name_node.range.end,
        };
    let mut parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>> = Vec::new();
    while let Some(parameter_node) = parse_gren_syntax_pattern_not_space_separated_node(state) {
        syntax_before_equals_key_symbol_end_location = parameter_node.range.end;
        parameters.push(parameter_node);
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    let maybe_result: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        if state.position.character <= u32::from(state.indent) {
            None
        } else {
            parse_gren_syntax_expression_space_separated_node(state)
        };
    GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_name_node.range.start,
            end: maybe_result
                .as_ref()
                .map(|node| node.range.end)
                .or_else(|| maybe_equals_key_symbol_range.map(|range| range.end))
                .unwrap_or(syntax_before_equals_key_symbol_end_location),
        },
        value: GrenSyntaxLetDeclaration::VariableDeclaration {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters: parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        },
    }
}
fn parse_gren_syntax_expression_string(state: &mut ParseState) -> Option<GrenSyntaxExpression> {
    parse_gren_string_triple_quoted(state)
        .map(|content| GrenSyntaxExpression::String {
            content: content,
            quoting_style: GrenSyntaxStringQuotingStyle::TripleQuoted,
        })
        .or_else(|| {
            parse_gren_string_single_quoted(state).map(|content| GrenSyntaxExpression::String {
                content: content,
                quoting_style: GrenSyntaxStringQuotingStyle::SingleQuoted,
            })
        })
}
fn parse_gren_syntax_expression_list(state: &mut ParseState) -> Option<GrenSyntaxExpression> {
    if !parse_symbol(state, "[") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    while parse_symbol(state, ",") {
        parse_gren_whitespace_and_comments(state);
    }
    let mut elements: Vec<GrenSyntaxNode<GrenSyntaxExpression>> = Vec::new();
    while let Some(expression_node) = parse_gren_syntax_expression_space_separated_node(state) {
        elements.push(expression_node);
        parse_gren_whitespace_and_comments(state);
        while parse_symbol(state, ",") {
            parse_gren_whitespace_and_comments(state);
        }
    }
    let _: bool = parse_symbol(state, "]");
    Some(GrenSyntaxExpression::Array(elements))
}
fn parse_gren_syntax_expression_operator_function_or_parenthesized(
    state: &mut ParseState,
) -> Option<GrenSyntaxExpression> {
    if !parse_symbol(state, "(") {
        return None;
    }
    parse_gren_whitespace_and_comments(state);
    Some(
        if let Some(operator_node) = parse_gren_operator_followed_by_closing_paren(state) {
            // needs to be this cursed to differentiate (-) and (-negated)
            GrenSyntaxExpression::OperatorFunction(operator_node)
        } else {
            let maybe_in_parens_0: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
                parse_gren_syntax_expression_space_separated_node(state);
            parse_gren_whitespace_and_comments(state);
            let _: bool = parse_symbol(state, ")");
            GrenSyntaxExpression::Parenthesized(maybe_in_parens_0.map(gren_syntax_node_box))
        },
    )
}
fn parse_gren_syntax_declaration_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxDeclaration>> {
    parse_gren_syntax_declaration_choice_type_or_type_alias_node(state)
        .or_else(|| parse_gren_syntax_declaration_port_node(state))
        .or_else(|| parse_gren_syntax_declaration_operator_node(state))
        .or_else(|| {
            if state.indent != 0 {
                return None;
            }
            parse_gren_syntax_declaration_variable_node(state)
        })
}
fn parse_gren_syntax_declaration_port_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxDeclaration>> {
    let port_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "port")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_name: Option<GrenSyntaxNode<Box<str>>> = parse_gren_lowercase_as_node(state);
    parse_gren_whitespace_and_comments(state);
    let maybe_colon_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, ":");
    parse_gren_whitespace_and_comments(state);
    let maybe_type: Option<GrenSyntaxNode<GrenSyntaxType>> =
        parse_gren_syntax_type_space_separated_node(state);
    let full_end_position: lsp_types::Position = maybe_type
        .as_ref()
        .map(|type_node| type_node.range.end)
        .or_else(|| maybe_colon_key_symbol_range.map(|range| range.end))
        .or_else(|| maybe_name.as_ref().map(|node| node.range.end))
        .unwrap_or(port_keyword_range.end);
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: port_keyword_range.start,
            end: full_end_position,
        },
        value: GrenSyntaxDeclaration::Port {
            name: maybe_name,
            colon_key_symbol_range: maybe_colon_key_symbol_range,
            type_: maybe_type,
        },
    })
}
fn parse_gren_syntax_declaration_operator_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxDeclaration>> {
    let infix_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "infix")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_direction: Option<GrenSyntaxNode<GrenSyntaxInfixDirection>> =
        parse_gren_syntax_infix_declaration_node(state);
    parse_gren_whitespace_and_comments(state);
    let precedence_start_position: lsp_types::Position = state.position;
    let maybe_precedence: Option<GrenSyntaxNode<i64>> =
        match parse_gren_unsigned_integer_base10_as_i64(state).and_then(Result::ok) {
            None => None,
            Some(precedence) => {
                let precedence_range: lsp_types::Range = lsp_types::Range {
                    start: precedence_start_position,
                    end: state.position,
                };
                parse_gren_whitespace_and_comments(state);
                Some(GrenSyntaxNode {
                    range: precedence_range,
                    value: precedence,
                })
            }
        };
    let _: bool = parse_symbol(state, "(");
    parse_gren_whitespace_and_comments(state);
    let maybe_operator_symbol: Option<GrenSyntaxNode<&str>> = parse_gren_operator_node(state);
    parse_gren_whitespace_and_comments(state);
    let _: bool = parse_symbol(state, ")");
    parse_gren_whitespace_and_comments(state);
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    let maybe_function: Option<GrenSyntaxNode<Box<str>>> = parse_gren_lowercase_as_node(state);
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: infix_keyword_range.start,
            end: state.position,
        },
        value: GrenSyntaxDeclaration::Operator {
            direction: maybe_direction,
            precedence: maybe_precedence,
            operator: maybe_operator_symbol,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            function: maybe_function,
        },
    })
}
fn parse_gren_syntax_infix_declaration_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxInfixDirection>> {
    let start_position: lsp_types::Position = state.position;
    let direction: GrenSyntaxInfixDirection =
        parse_symbol_as(state, "left", GrenSyntaxInfixDirection::Left)
            .or_else(|| parse_symbol_as(state, "right", GrenSyntaxInfixDirection::Right))
            .or_else(|| parse_symbol_as(state, "non", GrenSyntaxInfixDirection::Non))?;
    let end_position = state.position;
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_position,
            end: end_position,
        },
        value: direction,
    })
}
fn parse_gren_syntax_declaration_choice_type_or_type_alias_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxDeclaration>> {
    let type_keyword_range: lsp_types::Range = parse_gren_keyword_as_range(state, "type")?;
    parse_gren_whitespace_and_comments(state);
    let maybe_alias_keyword_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "alias");
    parse_gren_whitespace_and_comments(state);
    let maybe_name_node: Option<GrenSyntaxNode<Box<str>>> = parse_gren_uppercase_node(state);
    parse_gren_whitespace_and_comments(state);
    let mut syntax_before_equals_key_symbol_end_location: lsp_types::Position = maybe_name_node
        .as_ref()
        .map(|name_node| name_node.range.end)
        .or_else(|| maybe_alias_keyword_range.map(|range| range.end))
        .unwrap_or(type_keyword_range.end);
    let mut parameters: Vec<GrenSyntaxNode<Box<str>>> = Vec::new();
    while let Some(parameter_node) = parse_gren_lowercase_as_node(state) {
        syntax_before_equals_key_symbol_end_location = parameter_node.range.end;
        parameters.push(parameter_node);
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    Some(match maybe_alias_keyword_range {
        Some(alias_keyword_range) => {
            let maybe_type: Option<GrenSyntaxNode<GrenSyntaxType>> =
                if state.position.character <= u32::from(state.indent) {
                    None
                } else {
                    parse_gren_syntax_type_space_separated_node(state)
                };
            let full_end_location: lsp_types::Position = maybe_type
                .as_ref()
                .map(|type_node| type_node.range.end)
                .or_else(|| maybe_equals_key_symbol_range.map(|range| range.end))
                .unwrap_or(syntax_before_equals_key_symbol_end_location);
            GrenSyntaxNode {
                range: lsp_types::Range {
                    start: type_keyword_range.start,
                    end: full_end_location,
                },
                value: GrenSyntaxDeclaration::TypeAlias {
                    alias_keyword_range: alias_keyword_range,
                    name: maybe_name_node,
                    parameters: parameters,
                    equals_key_symbol_range: maybe_equals_key_symbol_range,
                    type_: maybe_type,
                },
            }
        }
        None => {
            let maybe_variant0_name: Option<GrenSyntaxNode<Box<str>>> =
                parse_gren_uppercase_node(state);
            parse_gren_whitespace_and_comments(state);
            let variant0_maybe_value: Option<GrenSyntaxNode<GrenSyntaxType>> =
                parse_gren_syntax_type_not_space_separated_node(state);
            let mut full_end_position: lsp_types::Position = maybe_variant0_name
                .as_ref()
                .map(|node| node.range.end)
                .or_else(|| maybe_equals_key_symbol_range.map(|range| range.end))
                .unwrap_or(syntax_before_equals_key_symbol_end_location);
            if let Some(variant0_value_node) = &variant0_maybe_value {
                full_end_position = variant0_value_node.range.end;
                parse_gren_whitespace_and_comments(state);
            }
            parse_gren_whitespace_and_comments(state);
            let mut variant1_up: Vec<GrenSyntaxChoiceTypeDeclarationTailingVariant> = Vec::new();
            while let Some(variant_node) =
                parse_gren_syntax_choice_type_declaration_trailing_variant_node(state)
            {
                variant1_up.push(variant_node.value);
                full_end_position = variant_node.range.end;
                parse_gren_whitespace_and_comments(state);
            }
            GrenSyntaxNode {
                range: lsp_types::Range {
                    start: type_keyword_range.start,
                    end: full_end_position,
                },
                value: GrenSyntaxDeclaration::ChoiceType {
                    name: maybe_name_node,
                    parameters: parameters,
                    equals_key_symbol_range: maybe_equals_key_symbol_range,
                    variant0_name: maybe_variant0_name,
                    variant0_value: variant0_maybe_value,
                    variant1_up: variant1_up,
                },
            }
        }
    })
}
fn parse_gren_syntax_choice_type_declaration_trailing_variant_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxChoiceTypeDeclarationTailingVariant>> {
    let or_key_symbol_range: lsp_types::Range = parse_symbol_as_range(state, "|")?;
    parse_gren_whitespace_and_comments(state);
    while parse_symbol(state, "|") {
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_name: Option<GrenSyntaxNode<Box<str>>> = parse_gren_uppercase_node(state);
    parse_gren_whitespace_and_comments(state);
    let maybe_value: Option<GrenSyntaxNode<GrenSyntaxType>> =
        parse_gren_syntax_type_not_space_separated_node(state);
    let mut full_end_position: lsp_types::Position = maybe_name
        .as_ref()
        .map(|node| node.range.end)
        .unwrap_or_else(|| or_key_symbol_range.end);
    if let Some(value_node) = &maybe_value {
        full_end_position = value_node.range.end;
        parse_gren_whitespace_and_comments(state);
    }
    Some(GrenSyntaxNode {
        range: lsp_types::Range {
            start: or_key_symbol_range.start,
            end: full_end_position,
        },
        value: GrenSyntaxChoiceTypeDeclarationTailingVariant {
            or_key_symbol_range: or_key_symbol_range,
            name: maybe_name,
            value: maybe_value,
        },
    })
}
fn parse_gren_syntax_declaration_variable_node(
    state: &mut ParseState,
) -> Option<GrenSyntaxNode<GrenSyntaxDeclaration>> {
    let start_name_node: GrenSyntaxNode<Box<str>> = parse_gren_lowercase_as_node(state)?;
    parse_gren_whitespace_and_comments(state);
    Some(match parse_symbol_as_range(state, ":") {
        None => parse_gren_syntax_declaration_variable_node_after_maybe_signature_and_name(
            state,
            start_name_node,
            None,
        ),
        Some(colon_key_symbol_range) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_type: Option<GrenSyntaxNode<GrenSyntaxType>> =
                parse_gren_syntax_type_space_separated_node(state);
            parse_gren_whitespace_and_comments(state);
            match parse_symbol_as_range(state, &start_name_node.value) {
                None => GrenSyntaxNode {
                    range: lsp_types::Range {
                        start: start_name_node.range.start,
                        end: maybe_type
                            .as_ref()
                            .map(|node| node.range.end)
                            .unwrap_or_else(|| colon_key_symbol_range.end),
                    },
                    value: GrenSyntaxDeclaration::Variable {
                        start_name: start_name_node,
                        signature: Some(GrenSyntaxVariableDeclarationSignature {
                            colon_key_symbol_range: colon_key_symbol_range,
                            type_: maybe_type,
                            implementation_name_range: None,
                        }),
                        parameters: vec![],
                        equals_key_symbol_range: None,
                        result: None,
                    },
                },
                Some(implementation_name_range) => {
                    parse_gren_whitespace_and_comments(state);
                    parse_gren_syntax_declaration_variable_node_after_maybe_signature_and_name(
                        state,
                        start_name_node,
                        Some(GrenSyntaxVariableDeclarationSignature {
                            colon_key_symbol_range: colon_key_symbol_range,
                            type_: maybe_type,
                            implementation_name_range: Some(implementation_name_range),
                        }),
                    )
                }
            }
        }
    })
}
fn parse_gren_syntax_declaration_variable_node_after_maybe_signature_and_name(
    state: &mut ParseState,
    start_name_node: GrenSyntaxNode<Box<str>>,
    maybe_signature: Option<GrenSyntaxVariableDeclarationSignature>,
) -> GrenSyntaxNode<GrenSyntaxDeclaration> {
    let mut syntax_before_equals_key_symbol_end_location: lsp_types::Position =
        match &maybe_signature {
            Some(signature) => signature
                .implementation_name_range
                .map(|range| range.end)
                .or_else(|| signature.type_.as_ref().map(|node| node.range.end))
                .unwrap_or(signature.colon_key_symbol_range.end),
            None => start_name_node.range.end,
        };
    let mut parameters: Vec<GrenSyntaxNode<GrenSyntaxPattern>> = Vec::new();
    while let Some(parameter_node) = parse_gren_syntax_pattern_not_space_separated_node(state) {
        syntax_before_equals_key_symbol_end_location = parameter_node.range.end;
        parameters.push(parameter_node);
        parse_gren_whitespace_and_comments(state);
    }
    let maybe_equals_key_symbol_range: Option<lsp_types::Range> = parse_symbol_as_range(state, "=");
    parse_gren_whitespace_and_comments(state);
    let maybe_result: Option<GrenSyntaxNode<GrenSyntaxExpression>> =
        if state.position.character <= u32::from(state.indent) {
            None
        } else {
            parse_gren_syntax_expression_space_separated_node(state)
        };
    GrenSyntaxNode {
        range: lsp_types::Range {
            start: start_name_node.range.start,
            end: maybe_result
                .as_ref()
                .map(|node| node.range.end)
                .or_else(|| maybe_equals_key_symbol_range.map(|range| range.end))
                .unwrap_or(syntax_before_equals_key_symbol_end_location),
        },
        value: GrenSyntaxDeclaration::Variable {
            start_name: start_name_node,
            signature: maybe_signature,
            parameters: parameters,
            equals_key_symbol_range: maybe_equals_key_symbol_range,
            result: maybe_result,
        },
    }
}
fn parse_gren_syntax_documented_declaration_followed_by_whitespace_and_comments_and_whatever_indented(
    state: &mut ParseState,
) -> Option<GrenSyntaxDocumentedDeclaration> {
    match parse_gren_documentation_comment_block_node(state) {
        None => parse_gren_syntax_declaration_node(state).map(|declaration_node| {
            parse_gren_whitespace_and_comments(state);
            GrenSyntaxDocumentedDeclaration {
                documentation: None,
                declaration: Some(declaration_node),
            }
        }),
        Some(documentation_node) => {
            parse_gren_whitespace_and_comments(state);
            let maybe_declaration: Option<GrenSyntaxNode<GrenSyntaxDeclaration>> =
                parse_gren_syntax_declaration_node(state);
            parse_gren_whitespace_and_comments(state);
            Some(GrenSyntaxDocumentedDeclaration {
                documentation: Some(documentation_node),
                declaration: maybe_declaration,
            })
        }
    }
}
fn parse_gren_syntax_module(module_source: &str) -> GrenSyntaxModule {
    let mut state: ParseState = ParseState {
        source: module_source,
        offset_utf8: 0,
        position: lsp_types::Position {
            line: 0,
            character: 0,
        },
        indent: 0,
        lower_indents_stack: vec![],
        comments: vec![],
    };
    parse_gren_whitespace_and_comments(&mut state);
    let maybe_header: Option<GrenSyntaxModuleHeader> = parse_gren_syntax_module_header(&mut state);
    parse_gren_whitespace_and_comments(&mut state);
    let maybe_module_documentation: Option<
        GrenSyntaxNode<Vec<GrenSyntaxNode<GrenSyntaxModuleDocumentationElement>>>,
    > = parse_gren_syntax_module_documentation_node(&mut state);
    parse_gren_whitespace_and_comments(&mut state);
    let mut imports: Vec<GrenSyntaxNode<GrenSyntaxImport>> = Vec::new();
    while let Some(import_node) = parse_gren_syntax_import_node(&mut state) {
        imports.push(import_node);
        parse_gren_whitespace_and_comments(&mut state);
    }
    let mut last_valid_end_offet_utf8: usize = state.offset_utf8;
    let mut last_parsed_was_valid: bool = true;
    let mut declarations: Vec<Result<GrenSyntaxDocumentedDeclaration, Box<str>>> =
        Vec::with_capacity(8);
    'parsing_delarations: loop {
        let offset_utf8_before_parsing_documeted_declaration: usize = state.offset_utf8;
        match parse_gren_syntax_documented_declaration_followed_by_whitespace_and_comments_and_whatever_indented(&mut state) {
            Some(documented_declaration) => {
                if !last_parsed_was_valid {
                    declarations.push(Err(Box::from(&module_source[last_valid_end_offet_utf8..offset_utf8_before_parsing_documeted_declaration])));
                }
                last_parsed_was_valid = true;
                declarations.push(Ok(documented_declaration));
                parse_gren_whitespace_and_comments(&mut state);
                last_valid_end_offet_utf8 = state.offset_utf8;
            }
            None => {
                parse_before_next_linebreak(&mut state);
                if parse_linebreak(&mut state) {
                    last_parsed_was_valid = false;
                } else {
                    break 'parsing_delarations;
                }
            }
        }
    }
    GrenSyntaxModule {
        header: maybe_header,
        documentation: maybe_module_documentation,
        comments: state.comments,
        imports: imports,
        declarations: declarations,
    }
}

fn string_replace_lsp_range(
    string: &mut String,
    range: lsp_types::Range,
    range_length: usize,
    replacement: &str,
) {
    let start_line_offset: usize =
        str_offset_after_n_lsp_linebreaks(string, range.start.line as usize);
    let start_offset: usize = start_line_offset
        + str_starting_utf8_length_for_utf16_length(
            &string[start_line_offset..],
            range.start.character as usize,
        );
    let range_length_utf8: usize =
        str_starting_utf8_length_for_utf16_length(&string[start_offset..], range_length);
    string.replace_range(
        start_offset..(start_offset + range_length_utf8),
        replacement,
    );
}
fn str_offset_after_n_lsp_linebreaks(str: &str, linebreak_count_to_skip: usize) -> usize {
    if linebreak_count_to_skip == 0 {
        return 0;
    }
    let mut offset_after_n_linebreaks: usize = 0;
    let mut encountered_linebreaks: usize = 0;
    'finding_after_n_linebreaks_offset: loop {
        if str[offset_after_n_linebreaks..].starts_with("\r\n") {
            encountered_linebreaks += 1;
            offset_after_n_linebreaks += 2;
            if encountered_linebreaks >= linebreak_count_to_skip {
                break 'finding_after_n_linebreaks_offset;
            }
        } else {
            match str[offset_after_n_linebreaks..].chars().next() {
                None => {
                    break 'finding_after_n_linebreaks_offset;
                }
                // see EOL in https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocuments
                Some('\r' | '\n') => {
                    encountered_linebreaks += 1;
                    offset_after_n_linebreaks += 1;
                    if encountered_linebreaks >= linebreak_count_to_skip {
                        break 'finding_after_n_linebreaks_offset;
                    }
                }
                Some(next_char) => {
                    offset_after_n_linebreaks += next_char.len_utf8();
                }
            }
        }
    }
    offset_after_n_linebreaks
}
fn str_starting_utf8_length_for_utf16_length(slice: &str, starting_utf16_length: usize) -> usize {
    let mut utf8_length: usize = 0;
    let mut so_far_length_utf16: usize = 0;
    'traversing_utf16_length: for char in slice.chars() {
        if so_far_length_utf16 >= starting_utf16_length {
            break 'traversing_utf16_length;
        }
        utf8_length += char.len_utf8();
        so_far_length_utf16 += char.len_utf16();
    }
    utf8_length
}
