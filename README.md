# @countinghouse/ch-step-redact

countinghouse step module: masks secrets and personal data in text lines before any line can reach a result.

**Status: preview.** Runs on [countinghouse](https://github.com/mchen6/countinghouse)
7.2 or later (unreleased at the time of writing). A step module of the countinghouse client packs: a `part`, loaded by a scenario and never listed to the model on its own.

Part of the countinghouse client packs. The design, the plan and the
acceptance tests live in [ch-packs](https://github.com/mchen6/ch-packs);
each package has its own repository (maintainer's decision, 2026-11-11).

## Development

```
npm ci
npm test
npm run validate   # packs the module and runs countinghouse-validate on the tarball
```

Pure JavaScript, Node 22.16 or later, no native module. CI runs on
Linux, macOS and Windows.

## Publishing

Releases are published by `.github/workflows/publish.yml` under npm
trusted publishing: a `v<version>` tag on a `main` commit whose
package.json carries that version. No npm token exists anywhere and no 2FA
code is typed for a release. One-time setup on npmjs.com, by the
maintainer: the package's first version is published by hand (`npm publish
--access public`, with 2FA); then **Settings → Trusted publishing → GitHub
Actions** with owner `mchen6`, repository `ch-step-redact`, workflow
`publish.yml`, allowing `npm publish` as well as `npm stage publish`;
then **Settings → Publishing access → Require two-factor authentication
and disallow tokens**. A new trusted-publisher configuration must publish
once within two days or it expires.

## License

Apache-2.0.
