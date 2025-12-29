/****************************
 * ESTAT
 ****************************/
let showOnlySensitive = false;
let allEndpoints = [];

/****************************
 * HELPERS
 ****************************/
function getVisibleEndpoints() {
  return showOnlySensitive
    ? allEndpoints.filter(e => e.sensitive)
    : allEndpoints;
}

function formatParams(params) {
  return params.length ? params.join(", ") : "-";
}

/****************************
 * RENDER
 ****************************/
function render() {
  const list = document.getElementById("list");
  list.textContent = ""; // netejem de manera segura

  const endpointsToShow = getVisibleEndpoints();

  if (!endpointsToShow.length) {
    const em = document.createElement("em");
    em.textContent = "No hi ha endpoints per mostrar";
    list.appendChild(em);
    return;
  }

  endpointsToShow.forEach((e, index) => {
    const div = createEndpointDiv(e, index);
    list.appendChild(div);
  });

  bindEndpointButtons();
}

// Crea un div d’endpoint segurament sense innerHTML
function createEndpointDiv(e, index) {
  const div = document.createElement("div");
  div.className = "endpoint" + (e.sensitive ? " sensitive" : "");

  // Mètode + badge
  const methodDiv = document.createElement("div");
  methodDiv.className = "method";
  methodDiv.textContent = e.method;
  if (e.sensitive) {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "SENSITIVE";
    methodDiv.appendChild(document.createTextNode(" ")); // espai abans badge
    methodDiv.appendChild(badge);
  }

  // URL
  const urlDiv = document.createElement("div");
  urlDiv.className = "url";
  urlDiv.textContent = e.url;

  // Params
  const paramsDiv = document.createElement("div");
  paramsDiv.textContent = `Params: ${formatParams(e.params)}`;

  // Hits
  const hitsDiv = document.createElement("div");
  hitsDiv.textContent = `Hits: ${e.count}`;

  // Botons
  const exportBtn = document.createElement("button");
  exportBtn.className = "export";
  exportBtn.dataset.index = index;
  exportBtn.textContent = "Exporta";

  const copyBtn = document.createElement("button");
  copyBtn.className = "copy";
  copyBtn.dataset.index = index;
  copyBtn.textContent = "Copia";

  div.append(methodDiv, urlDiv, paramsDiv, hitsDiv, exportBtn, copyBtn);
  return div;
}

/****************************
 * BINDINGS DINÀMICS
 ****************************/
function bindEndpointButtons() {
  document.querySelectorAll(".export")
    .forEach(btn => btn.addEventListener("click", exportEndpoint));

  document.querySelectorAll(".copy")
    .forEach(btn => btn.addEventListener("click", copyEndpoint));
}

/****************************
 * ACCIONS
 ****************************/
function exportEndpoint(e) {
  const endpoint = getVisibleEndpoints()[e.target.dataset.index];

  const blob = new Blob([JSON.stringify(endpoint, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = "endpoint.json";
  a.click();

  URL.revokeObjectURL(url);
}

function copyEndpoint(e) {
  const endpoint = getVisibleEndpoints()[e.target.dataset.index];
  const text = `${endpoint.method} --> ${endpoint.url} --> Params: ${formatParams(endpoint.params)}`;

  navigator.clipboard.writeText(text).then(() => {
    const btn = e.target;
    const original = btn.textContent;
    btn.textContent = "Copiat!";
    setTimeout(() => { btn.textContent = original; }, 1000);
  });
}

function copyVisibleEndpoints() {
  const endpoints = getVisibleEndpoints();
  if (!endpoints.length) return;

  const text = endpoints.map(e => `Method: ${e.method}
URL: ${e.url}
Params: ${formatParams(e.params)}`).join("\n\n");

  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copyVisible");
    const original = btn.textContent;
    btn.textContent = "Copiat!";
    setTimeout(() => { btn.textContent = original; }, 1200);
  });
}

/****************************
 * INIT
 ****************************/
browser.storage.local.get("endpoints").then(data => {
  allEndpoints = data.endpoints || [];
  render();
});

/****************************
 * BOTONS PRINCIPALS
 ****************************/
document.getElementById("toggleSensitive").addEventListener("click", () => {
  showOnlySensitive = !showOnlySensitive;
  document.getElementById("toggleSensitive").textContent =
    showOnlySensitive ? "Mostra tots" : "Només sensibles";
  render();
});

document.getElementById("copyVisible").addEventListener("click", copyVisibleEndpoints);

document.getElementById("clear").addEventListener("click", () => {
  browser.runtime.sendMessage({ action: "clear-endpoints" });
  allEndpoints = [];
  render();
});
