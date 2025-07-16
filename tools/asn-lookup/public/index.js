async function lookupAsnOnBackend(query) {
    try {
        const response = await fetch(`/api/lookup?asn=${encodeURIComponent(query)}`);
        if (!response.ok) {
            const errorInfo = await response.json();
            return { Error: errorInfo.Error || `Server returned an error: ${response.status}` };
        }
        return await response.json();
    } catch (error) {
        return { Error: "Failed to connect to the server. Please try again later." };
    }
}

const container = document.createElement("div");
container.className = "container";
container.style.maxWidth = "1150px";
container.style.margin = "30px auto";
container.style.background = "#fff";
container.style.borderRadius = "12px";
container.style.boxShadow = "0 2px 8px rgba(0,0,0,0.08)";
container.style.padding = "32px 32px 24px 32px";

document.getElementById("app").appendChild(container);

const title = document.createElement("h1");
title.textContent = "ASN Lookup";
title.style.fontSize = "2rem";
title.style.fontWeight = "600";
title.style.marginBottom = "8px";
container.appendChild(title);

const desc = document.createElement("div");
desc.textContent = "Retrieve detailed information about an Autonomous System Number.";
desc.style.color = "#555";
desc.style.marginBottom = "24px";
container.appendChild(desc);

const form = document.createElement("form");
form.className = "search-box";
form.style.display = "flex";
form.style.gap = "12px";
form.style.marginBottom = "24px";
container.appendChild(form);

const input = document.createElement("input");
input.type = "text";
input.name = "asn";
input.placeholder = "Enter ASN (e.g. AS7922)";
input.required = true;
input.style.flex = "1";
input.style.padding = "12px";
input.style.border = "1px solid #d1d5db";
input.style.borderRadius = "6px";
input.style.fontSize = "1rem";
input.style.boxShadow = "0 1px 2px rgba(0,0,0,0.03)";
form.appendChild(input);

const button = document.createElement("button");
button.type = "submit";
button.textContent = "Lookup";
button.style.background = "#7a0000";
button.style.color = "#fff";
button.style.border = "none";
button.style.borderRadius = "6px";
button.style.padding = "0 28px";
button.style.fontSize = "1rem";
button.style.fontWeight = "600";
button.style.cursor = "pointer";
button.style.boxShadow = "0 1px 2px rgba(0,0,0,0.04)";
button.onmouseover = () => { if(!button.disabled) button.style.background = "#5a0000"; };
button.onmouseout = () => { if(!button.disabled) button.style.background = "#7a0000"; };
form.appendChild(button);

const resultsDiv = document.createElement("div");
resultsDiv.style.position = "relative";
resultsDiv.style.borderRadius = "12px";
resultsDiv.style.background = "#fff";
resultsDiv.style.padding = "24px 32px 16px 32px";
resultsDiv.style.marginBottom = "32px";
resultsDiv.style.border = "1px solid #e5e7eb";

form.onsubmit = async (e) => {
    e.preventDefault();
    const query = input.value.trim();
    if (!query) return;

    button.disabled = true;
    button.textContent = "Looking up...";
    button.style.background = "#555";
    button.style.cursor = "wait";
    
    if (!container.contains(resultsDiv)) {
        container.appendChild(resultsDiv);
    }
    
    renderResults(query, { Status: "Loading..." });

    const asnInfo = await lookupAsnOnBackend(query);
    
    renderResults(query, asnInfo);

    button.disabled = false;
    button.textContent = "Lookup";
    button.style.background = "#7a0000";
    button.style.cursor = "pointer";
};

function renderResults(query, asnInfo) {
    resultsDiv.innerHTML = "";
    if (!query) return;

    const header = document.createElement("div");
    header.style.fontSize = "1.2rem";
    header.style.fontWeight = "500";
    header.style.marginBottom = "16px";
    header.innerHTML = `ASN Information for <b>${escapeHtml(query)}</b>`;
    resultsDiv.appendChild(header);

    if (asnInfo && asnInfo.Error) {
        const errorDiv = document.createElement('div');
        errorDiv.style.color = '#c00';
        errorDiv.style.background = '#ffebee';
        errorDiv.style.padding = '12px';
        errorDiv.style.borderRadius = '6px';
        errorDiv.textContent = asnInfo.Error;
        resultsDiv.appendChild(errorDiv);
        return;
    }
    
    const table = document.createElement("table");
    table.style.width = "100%";
    table.style.borderCollapse = "collapse";
    table.style.marginTop = "8px";
    const tbody = document.createElement("tbody");

    if (asnInfo && typeof asnInfo === 'object' && Object.keys(asnInfo).length > 0) {
        Object.entries(asnInfo).forEach(([field, value]) => {
            if (!value) return;
            
            const tr = document.createElement("tr");
            tr.style.borderBottom = "1px solid #e5e7eb";

            const tdField = document.createElement("td");
            tdField.textContent = field.replace(/_/g, ' ');
            tdField.style.padding = "12px 8px";
            tdField.style.fontWeight = "600";
            tdField.style.color = "#333";
            tdField.style.verticalAlign = "top";
            tdField.style.width = "180px";

            const tdValue = document.createElement("td");
            tdValue.textContent = value;
            tdValue.style.padding = "12px 8px";
            tdValue.style.wordBreak = "break-all";
            tdValue.style.whiteSpace = "pre-wrap";

            tr.appendChild(tdField);
            tr.appendChild(tdValue);
            tbody.appendChild(tr);
        });
    }

    table.appendChild(tbody);
    resultsDiv.appendChild(table);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, (tag) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;' 
  }[tag] || tag));
}
