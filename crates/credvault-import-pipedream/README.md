# credvault-import-pipedream

An offline tool that turns a local clone of [Pipedream's open-source
components](https://github.com/PipedreamHQ/pipedream/tree/master/components) into a
directory of credvault provider plugin manifests. The output is an ordinary plugin
directory — point `VAULT_PLUGIN_DIRS` at it and the apps load exactly like the shipped
defaults.

This is a developer/operator tool, not part of the published library (`publish = false`).
It depends on the `credvault` crate only for its manifest-extraction logic.

```bash
git clone --depth 1 https://github.com/PipedreamHQ/pipedream
cargo run -p credvault-import-pipedream -- pipedream/components --out-dir plugins/pipedream
```

It writes one `<id>.json` per loadable app, plus a `*.todo.json` overlay skeleton for
OAuth apps whose endpoints Pipedream does not publish (fill those in from each provider's
own OAuth docs and re-run with `--overlay`). Every emitted manifest is validated against
the same rules the runtime loader uses.

See the [repository README](../../README.md#from-pipedreams-catalog) for the full workflow
and the important Pipedream-side limitations, and [plugins/README.md](../../plugins/README.md)
for the manifest contract.
