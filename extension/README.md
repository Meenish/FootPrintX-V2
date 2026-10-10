# FootprintX browser extension

Developer build, installation, permissions, privacy model and tests: see [docs/EXTENSION.md](../docs/EXTENSION.md).

```bash
FX_API_BASE=http://localhost:5000 FX_APP_URL=http://localhost:5173 npm run build -w extension
# Chrome/Edge: chrome://extensions → Developer mode → Load unpacked → extension/dist/chromium
# Firefox:     about:debugging → This Firefox → Load Temporary Add-on → extension/dist/firefox/manifest.json
npm test -w extension
```
