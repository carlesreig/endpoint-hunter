// Create DevTools panel to host `panel.html` (works with callback or promise versions)
function createDevToolsPanel() {
  if (!browser?.devtools?.panels?.create) {
    console.warn('⚠️ devtools.panels.create not available in this runtime');
    return;
  }
  try {
    const maybePromise = browser.devtools.panels.create("Endpoint Hunter", "../../icons/icon-48.png", "../panel/panel.html");

    function attachOnShown(panel, source) {
      try {
        if (panel && panel.onShown && typeof panel.onShown.addListener === 'function') {
          panel.onShown.addListener((panelWindow) => {
            // log(`🔔 DevTools panel shown (${source}). Refreshing inspected domain and rendering panel UI.`);
            try {
              // If the panel's page exposes updateDomainFilter/render, call them
              if (panelWindow && typeof panelWindow.updateDomainFilter === 'function') {
                panelWindow.updateDomainFilter().then(() => {
                  if (typeof panelWindow.render === 'function') panelWindow.render();
                }).catch(err => console.error('❌ updateDomainFilter() threw in panelWindow:', err));
              } else if (panelWindow && typeof panelWindow.render === 'function') {
                // At least re-render
                panelWindow.render();
              }
            } catch (e) {
              console.error('❌ Error invoking panelWindow functions onShown:', e);
            }
          });
        }
      } catch (e) {
        console.error('❌ Error attaching onShown listener:', e);
      }
    }

    if (maybePromise && typeof maybePromise.then === 'function') {
      maybePromise.then(panel => {
        // log('✅ DevTools panel created (promise)');
        attachOnShown(panel, 'promise');
      }).catch(err => console.error('❌ Error creating panel (promise)', err));
    } else {
      try {
        browser.devtools.panels.create("Endpoint Hunter", "icons/icon-48.png", "../panel/panel.html", function(panel) {
          // log('✅ DevTools panel created (callback)');
          attachOnShown(panel, 'callback');
        });
      } catch (e) {
        console.error('❌ Error creating panel (callback)', e);
      }
    }
  } catch (err) {
    console.error('❌ Error creating DevTools panel:', err);
  }
}
createDevToolsPanel();
