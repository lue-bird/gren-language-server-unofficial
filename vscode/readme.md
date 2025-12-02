vscode extension for [gren](https://gren-lang.org/) using [gren-language-server-unofficial](https://github.com/lue-bird/gren-language-server-unofficial). Having it installed is a strict requirement.

## settings
- `gren-language-server-unofficial.grenPath: string`: compiler executable, default `"gren"`
- `gren-language-server-unofficial.grenTestPath: string`: test runner executable, default `"gren-test"`
- `gren-language-server-unofficial.grenFormatPath: "builtin" | string`: formatter executable, default `"gren-format"`. `"builtin"` is a fast rust formatter that is mostly but not fully compatible

## setup for developing
```bash
npm install
```
Open in vscode and press `F5` (or navigate to "run and debug" and click the start button) to open a new window with the compiled extension enabled.
