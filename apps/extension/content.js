// Content-script bootstrap. Declared as a classic script in manifest.json so
// it loads at document_start; it then dynamic-imports the ES module
// interceptor (which can in turn `import` its peers).

(async () => {
  try {
    const url = chrome.runtime.getURL("utils/intercept.js");
    const mod = await import(url);
    const enabled = mod.bootstrap();
    if (enabled && console && console.debug) {
      console.debug("[Aetherix] guardrails active on", location.hostname);
    }
  } catch (err) {
    // Never throw into the host page.
    if (console && console.warn) {
      console.warn("[Aetherix] failed to initialize guardrails", err);
    }
  }
})();
