import * as vscode from "vscode";
import {
  LanguageClientOptions,
} from "vscode-languageclient";
import {
  LanguageClient,
  ServerOptions,
} from "vscode-languageclient/node";
import * as child_process from "node:child_process";

let client: LanguageClient | null = null;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const languageServerExecutableName: string =
    // when debugging, replace with:
    // "<PATH>/gren-language-server-unofficial/target/debug/gren-language-server-unofficial";
    "gren-language-server-unofficial";
  context.subscriptions.push(vscode.commands.registerCommand("gren.commands.restart", async () => {
    if (client !== null) {
      await client.stop();
      await client.start();
    }
  }));

  const serverOptions: ServerOptions = async () => {
    return child_process.spawn(languageServerExecutableName)
  };
  const clientOptions: LanguageClientOptions = {
    diagnosticCollectionName: "gren",
    documentSelector: [
      {
        scheme: "file",
        language: "gren",
      },
      {
        scheme: "file",
        language: "json",
      },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/{gren.json,*.gren}"),
      // documentation says this is deprecated but how else
      // would you get the client to ping on configuration changes?
      configurationSection: "gren-language-server-unofficial"
    },
    // technically not necessary but saves an unnecessary roundtrip
    initializationOptions: getSettings(vscode.workspace.getConfiguration().get<IClientSettings>("gren-language-server-unofficial")),
  };
  client = new LanguageClient(
    "gren-language-server-unofficial",
    "gren",
    serverOptions,
    clientOptions,
  );
  await client.start();
}
function getSettings(config: IClientSettings | undefined): object {
  return config
    ? {
      grenPath: config.grenPath,
      grenFormatPath: config.grenFormatPath,
    }
    : {};
}
export interface IClientSettings {
  grenFormatPath: "builtin" | string;
  grenPath: string;
}

export function deactivate(): Thenable<void> | undefined {
  if (client !== null) {
    return client.stop()
  }
  return undefined;
}
