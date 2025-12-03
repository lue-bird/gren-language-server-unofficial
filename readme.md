Unofficial LSP language server for [gren](https://gren-lang.org/), focusing on performance and reliability.
To use, [install rust](https://rust-lang.org/tools/install/) and
```bash
cargo +nightly install --git https://github.com/lue-bird/gren-language-server-unofficial
```
Then point your editor to `gren-language-server-unofficial`, see also [specific setups](#editor-setups).

You can also set their paths in the language server settings:
- `gren-language-server-unofficial.grenPath: string`: compiler executable, default `"gren"`
- `gren-language-server-unofficial.grenFormatPath: "builtin" | string`: formatter executable, default `"builtin"`. `"builtin"` is a fast, unofficial rust formatter

## TODO
- support non-punned record patterns
- remove special handling of record type alias constructors
- remove support for 2+ variant values on pattern and custom type declaration
- TODO edit the vscode language grammar (ugh)

## editor setups
feel free to contribute, as I only use vscodium

### vscode-like
#### pre-built
1. download https://github.com/lue-bird/gren-language-server-unofficial/blob/main/vscode/gren-language-server-unofficial-0.0.1.vsix
2. open the command bar at the top and select: `>Extensions: Install from VSIX`
#### build from source
1. clone this repo
2. open `vscode/`
3. run `npm run package` to create the `.vsix`
4. open the command bar at the top and select: `>Extensions: Install from VSIX`
#### server only
There is no built-in language server bridge as far as I know but you can install an extension like [vscode-generic-lsp-proxy](https://github.com/mjmorales/vscode-generic-lsp-proxy) that will work for any language server.
Then add a `.vscode/lsp-proxy.json` like
```json
[
  {
    "languageId": "gren",
    "command": "gren-language-server-unofficial",
    "fileExtensions": [
      ".json",
      ".gren"
    ]
  }
]
```

### helix
write to `~/.config/helix/languages.toml`:
```toml
[language-server.gren-language-server-unofficial]
command = "gren-language-server-unofficial"
[[language]]
name = "gren"
scope = "source.gren"
injection-regex = "gren"
roots = ["gren.json"]
file-types = ["gren", "json"]
comment-token = "--"
block-comment-tokens = { start = "{-", end = "-}" }
indent = { tab-width = 4, unit = "    " }
language-servers = [ "gren-language-server-unofficial" ]
auto-format = true
```

## not planned
- type inference
- directly integrating test running and similar
- codelens, workspace symbols, code folding, linked editing
- `gren.json` help

## not sure (Please give me feedback on this)
- show all module exposes when hovering `(..)` (only if I have time and there is interest)
- add code actions like "expose (including variants)", "inline", "inline all uses" (leaning towards no as it is fairly complicated, though it is very useful for sure)
- show function parameter names (leaning towards no, as they are often confusing if they are curried, reveal non-exposed variant patterns, have more parameters than the type suggests, are undescriptive etc)
- currently, an exposed member will still be suggested even when a local module-declared reference/local binding with the same name exists. Likewise, a local module-declared reference will still be suggested even when a local binding with the same name exists. (somewhat easily fixable but I don't really see the harm in directly showing this shadowing in your face)
- your idea 👀

## known limitations
- It is possible that an gren module belongs to multiple projects when source directory paths overlap between projects. This throws a wrench in pretty much all existing code (likely internal document source desync and a more limited lsp feature range in one of the containing projects).
  This situation is, I assume, fixable by special-casing their storage and handling but it would require a _lot_ of work

## setup for developing
Rebuild the project with
```bash
cargo build
```
Then point your editor to the created `???/target/debug/gren-language-server-unofficial`.

### log of failed optimizations
- switching to mimalloc, ~>25% faster (really nice) at the cost of 25% more memory consumption.
  Might be worth for some people but I'm already worried about our memory footprint!
- `declarations.shrink_to_fit();` saves around 0.6% of memory at the cost of a bit of speed
- upgrading `lto` to `"thin"` to `"fat"` both improve runtime speed by ~13% compared to the default (and reduce binary size) but increase build time by about 30% (default to thin) and 15% (thin to fat).
  As this prolongs installation and prevents people from quickly trying it, the default is kept.
  If this language server get distributed as a binary or people end up using this language server a lot, this `"thin"` might become a reasonable trade-off.

### optimizations to try
- reparse incrementally (somewhat easy to implement but somehow it's for me at least pretty much fast enough already without? More data points welcome)
- switch to `position_encoding: Some(lsp_types::PositionEncodingKind::UTF8)`. This makes source edits and parsing easier and faster at the cost of compatibility with lsp clients below version 3.17.0. Is that acceptable? (leaning towards yes).
  Also validate if gren --report region column is UTF-8 or UTF-16 (seems to be UTF-16 strangely)
- if memory consumptions turns out to be a problem, stop storing the source in memory
  and request full file content on each change (potentially only for dependencies).
  This adds complexity and is slower so only if necessary.
- in syntax tree, use separate range type for single-line tokens like keywords, symbols, names etc to save on memory consumption
- switch most syntax tree `Box<str>`s to https://docs.rs/smallstr/0.3.1/smallstr/
  to for example speed up collecting references (e.g. for rename)
- in syntax tree, use `Box<[]>` instead of `Vec` for common nodes like call arguments
- on init, read modules in parallel, not just projects, to even out difference in project size (seems not worth using threads, maybe something more lightweight?)
