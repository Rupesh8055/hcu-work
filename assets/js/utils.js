window.CJ = window.CJ || {};
(function() {
    // Try to find the root of the tools by looking for assets/js/utils.js
    const scripts = document.getElementsByTagName('script');
    for (let s of scripts) {
        if (s.src && s.src.includes('assets/js/utils.js')) {
            window.CJ.basePath = s.src.replace('assets/js/utils.js', '');
            break;
        }
    }
    if (!window.CJ.basePath) {
        // Fallback: try to guess from location
        if (window.location.pathname.includes('/tools/')) {
            window.CJ.basePath = window.location.origin + '/tools/';
        } else {
            window.CJ.basePath = window.location.origin + '/';
        }
    }
})();
window.CJ.escapeHtml = function (text) {
  if (!text) return text;
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};
window.CJ.initFormatTabs = function (
  formatTabs,
  htmlView,
  jsonView,
  onTabChange,
) {
  if (!formatTabs || !htmlView || !jsonView) return;
  formatTabs.forEach((tab) => {
    tab.addEventListener("click", function () {
      window.CJ.currentFormat = this.dataset.format;
      formatTabs.forEach((t) => t.classList.remove("active"));
      this.classList.add("active");
      if (this.dataset.format === "html") {
        htmlView.style.display = "block";
        jsonView.style.display = "none";
      } else {
        htmlView.style.display = "none";
        jsonView.style.display = "block";
      }
      if (onTabChange) onTabChange(this.dataset.format);
    });
  });
};
window.CJ.initCopyBtn = function (copyBtn, htmlView, jsonView) {
  if (!copyBtn) return;
  copyBtn.addEventListener("click", function () {
    const textToCopy =
      window.CJ.currentFormat === "html"
        ? htmlView.textContent
        : jsonView.textContent;
    navigator.clipboard.writeText(textToCopy).then(() => {
      const originalTitle = this.title;
      this.title = "Copied!";
      const originalHTML = this.innerHTML;
      this.innerHTML =
        '<svg viewBox="0 0 24 24" fill="none" stroke="green" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      setTimeout(() => {
        this.title = originalTitle;
        this.innerHTML = originalHTML;
      }, 2000);
    });
  });
};
window.CJ.initDownloadBtn = function (
  downloadBtn,
  htmlView,
  jsonView,
  inputElem,
  toolName,
  getCurrentData,
) {
  if (!downloadBtn) return;
  downloadBtn.addEventListener("click", function () {
    const currentData = getCurrentData ? getCurrentData() : null;
    if (!currentData) return;
    const currentFormat = window.CJ.currentFormat || "html";
    const content =
      currentFormat === "html"
        ? htmlView.innerHTML
        : JSON.stringify(currentData, null, 2);
    const blob = new Blob([content], {
      type: currentFormat === "html" ? "text/html" : "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const val = inputElem ? inputElem.value.trim() : "export";
    a.download = `${toolName}-${val}.${currentFormat}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
};
window.CJ.getParam = function (name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
};

window.CJ.autoLookup = function (formId, inputId, paramName = null) {
  const form = document.getElementById(formId);
  const input = document.getElementById(inputId);
  if (!form || !input) return;

  const query = window.CJ.getParam(paramName) || 
                window.CJ.getParam('domain') || 
                window.CJ.getParam('host') || 
                window.CJ.getParam('ip') || 
                window.CJ.getParam('url') ||
                window.CJ.getParam('q');

  if (query) {
    input.value = query;

    setTimeout(() => {
      form.dispatchEvent(new Event('submit'));
    }, 100);
  }
};

window.CJ.loadHeaderFooter = function(relPath = "") {
    ["header", "footer"].forEach((id) => {
        const paths = [
            `/tools/${id}.html`,
            `${relPath}${id}.html`,
            `/${id}.html`,
            `../${id}.html`,
            `../../${id}.html`,
            `../../../${id}.html`
        ];
        
        const tryPath = (index) => {
            if (index >= paths.length) return;
            fetch(paths[index])
                .then(r => {
                    if (!r.ok) throw new Error("Not found");
                    return r.text();
                })
                .then(html => {
                    const el = document.getElementById(`${id}-include`);
                    if (el) el.innerHTML = html;
                })
                .catch(() => tryPath(index + 1));
        };
        tryPath(0);
    });
};

window.CJ.ensureLeaflet = function(callback) {
    if (typeof L !== 'undefined') {
        if (callback) callback();
        return;
    }
    
    const paths = [
        (window.CJ.basePath || '../../') + 'assets/leaflet/leaflet.js',
        'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
        '/tools/assets/leaflet/leaflet.js'
    ];
    
    const tryLoad = (index) => {
        if (index >= paths.length) {
            console.error('Leaflet could not be loaded from any source');
            const mapDiv = document.getElementById("map") || document.getElementById("mapContainer");
            if (mapDiv) mapDiv.innerHTML = '<div style="padding:20px;text-align:center;color:red;">Error [v1.1]: Map library (Leaflet) could not be loaded. Please hard-reload your browser (Ctrl+F5).</div>';
            return;
        }
        const script = document.createElement('script');
        script.src = paths[index];
        script.onload = () => {
            if (callback) callback();
        };
        script.onerror = () => tryLoad(index + 1);
        document.head.appendChild(script);
    };
    
    // Also ensure CSS
    const cssPath = (window.CJ.basePath || '../../') + 'assets/leaflet/leaflet.css';
    if (!document.querySelector('link[href*="leaflet.css"]')) {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = cssPath;
        document.head.appendChild(link);
    }
    
    tryLoad(0);
};

window.CJ.renderMap = function(containerId, lat, lon, info) {
    const mapDiv = document.getElementById(containerId);
    if (!mapDiv) return;
    mapDiv.style.display = "block";
    
    const latitude = parseFloat(lat);
    const longitude = parseFloat(lon);

    if (isNaN(latitude) || isNaN(longitude) || (latitude === 0 && longitude === 0)) {
        if (window.cjMapInstance) { window.cjMapInstance.remove(); window.cjMapInstance = null; }
        mapDiv.style.height = '80px';
        mapDiv.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#666;font-style:italic;background:#f1f5f9;border-radius:8px;border:1px dashed #cbd5e0;">Location map not available for this IP address</div>';
        return;
    }

    mapDiv.style.height = '400px';

    try {
        if (window.cjMapInstance) { window.cjMapInstance.remove(); window.cjMapInstance = null; }
        mapDiv.innerHTML = "";
        
        const innerContainerId = containerId + '-inner-' + Date.now();
        const container = document.createElement('div');
        container.id = innerContainerId;
        container.style.height = '100%';
        container.style.width = '100%';
        container.style.borderRadius = '8px';
        mapDiv.appendChild(container);

        window.cjMapInstance = L.map(innerContainerId).setView([latitude, longitude], 12);
        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18,
        }).addTo(window.cjMapInstance);

        const escapeHtml = window.CJ.escapeHtml;
        const popupContent = `
            <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 5px;">
                <strong style="display:block;margin-bottom:6px;color:#7a0000;font-size:1.1rem;">${escapeHtml(info.city || "Unknown")}, ${escapeHtml(info.country || "Unknown")}</strong>
                <div style="color:#444;margin-bottom:4px;display:flex;align-items:center;gap:6px;">
                <svg style="width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                IP: ${escapeHtml(info.ip || "")}
                </div>
                ${info.isp ? '<div style="color:#666;font-size:0.85rem;border-top:1px solid #eee;padding-top:6px;margin-top:6px;">ISP: ' + escapeHtml(info.isp) + "</div>" : ""}
            </div>
            `;
        L.marker([latitude, longitude])
            .addTo(window.cjMapInstance)
            .bindPopup(popupContent)
            .openPopup();

        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 50);
        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 300);
        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 800);
    } catch (e) {
        console.error("Leaflet error:", e);
        mapDiv.innerHTML = `<div class="map-placeholder">Error: ${e.message}. Please ensure you have an active internet connection.</div>`;
    }
};

window.CJ.renderPathMap = function(containerId, hops) {
    const mapDiv = document.getElementById(containerId);
    if (!mapDiv) return;
    mapDiv.style.display = "block";
    
    let validPoints = [];
    hops.forEach(hop => {
        const lat = parseFloat(hop.lat);
        const lon = parseFloat(hop.lon);
        if (!isNaN(lat) && !isNaN(lon) && (lat !== 0 || lon !== 0)) {
            validPoints.push({ lat, lon, hop });
        }
    });

    if (validPoints.length === 0) {
        if (window.cjMapInstance) { window.cjMapInstance.remove(); window.cjMapInstance = null; }
        mapDiv.style.height = '80px';
        mapDiv.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#666;font-style:italic;background:#f1f5f9;border-radius:8px;border:1px dashed #cbd5e0;">Geographic route map not available for this trace</div>';
        return;
    }

    mapDiv.style.height = '400px';

    try {
        if (window.cjMapInstance) { window.cjMapInstance.remove(); window.cjMapInstance = null; }
        mapDiv.innerHTML = "";
        
        const innerContainerId = containerId + '-inner-' + Date.now();
        const container = document.createElement('div');
        container.id = innerContainerId;
        container.style.height = '100%';
        container.style.width = '100%';
        container.style.borderRadius = '8px';
        mapDiv.appendChild(container);

        window.cjMapInstance = L.map(innerContainerId).setView([20, 0], 2);
        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18,
        }).addTo(window.cjMapInstance);

        const escapeHtml = window.CJ.escapeHtml;
        const latlngs = [];
        
        validPoints.forEach(p => {
            const pos = [p.lat, p.lon];
            latlngs.push(pos);
            const hop = p.hop;
            
            const popupContent = `
                <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 5px;">
                    <strong style="display:block;margin-bottom:6px;color:#7a0000;font-size:1.1rem;">Hop ${hop.hop}</strong>
                    <div style="color:#444;margin-bottom:4px;display:flex;align-items:center;gap:6px;">
                        IP: ${escapeHtml(hop.ip || "")}
                    </div>
                    <div style="color:#666;font-size:0.85rem;">Loc: ${escapeHtml(hop.location)}</div>
                    ${hop.isp ? '<div style="color:#666;font-size:0.85rem;border-top:1px solid #eee;padding-top:6px;margin-top:6px;">ISP: ' + escapeHtml(hop.isp) + "</div>" : ""}
                    ${hop.asn ? '<div style="color:#666;font-size:0.85rem;">ASN: ' + escapeHtml(hop.asn) + "</div>" : ""}
                </div>
            `;
            L.marker(pos).addTo(window.cjMapInstance).bindPopup(popupContent);
        });

        if (latlngs.length > 1) {
            const polyline = L.polyline(latlngs, { color: '#7a0000', weight: 3, opacity: 0.7, dashArray: '5, 10' }).addTo(window.cjMapInstance);
            window.cjMapInstance.fitBounds(polyline.getBounds(), { padding: [50, 50] });
        } else {
            window.cjMapInstance.setView(latlngs[0], 6);
        }

        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 50);
        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 300);
        setTimeout(() => { if (window.cjMapInstance) window.cjMapInstance.invalidateSize(); }, 800);
    } catch (e) {
        console.error("Leaflet error:", e);
        mapDiv.innerHTML = `<div class="map-placeholder">Error: ${e.message}. Please ensure you have an active internet connection.</div>`;
    }
};
