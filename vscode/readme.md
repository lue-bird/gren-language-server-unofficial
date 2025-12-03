vscode extension for [gren](https://gren-lang.org/) using [gren-language-server-unofficial](https://github.com/lue-bird/gren-language-server-unofficial). Having it installed is a strict requirement.

## settings
- `gren-language-server-unofficial.grenPath: string`: compiler executable, default `"gren"`. If the language server can't find it in the `$PATH`, please set this option to the path that `which gren` prints :)
- `gren-language-server-unofficial.grenFormatPath: "builtin" | string`: formatter executable, default `"builtin"`. `"builtin"` is a fast, unofficial rust formatter

## setup for developing
```bash
npm install
```
Open in vscode and press `F5` (or navigate to "run and debug" and click the start button) to open a new window with the compiled extension enabled.
