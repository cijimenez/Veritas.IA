// Archivo: static/js/verify-button.js
(function() {
    console.log("Script de botón de verificación cargado");
    
    // Función para añadir el botón de verificación a todos los popups
    function addVerifyButton() {
        // Buscar todos los popups abiertos
        const popups = document.querySelectorAll('.leaflet-popup-content');
        console.log("Popups encontrados:", popups.length);
        
        popups.forEach(popup => {
            // Verificar si ya tiene el botón
            if (!popup.querySelector('.verify-btn')) {
                // Buscar el ID del reporte a través de los botones de voto
                const voteBtn = popup.querySelector('.vote-btn');
                if (voteBtn) {
                    const reportId = voteBtn.getAttribute('data-report-id');
                    
                    if (reportId) {
                        console.log("Añadiendo botón de verificación al reporte:", reportId);
                        
                        // Crear el contenedor del botón
                        const btnContainer = document.createElement('div');
                        btnContainer.style.marginTop = '10px';
                        
                        // Crear el botón
                        btnContainer.innerHTML = `
                            <a href="/verify_report.html?report_id=${reportId}" 
                               class="verify-btn" 
                               style="display: block; width: 100%; text-align: center; padding: 8px; background-color: #007bff; color: white; border-radius: 5px; text-decoration: none; font-weight: bold;">
                                <i class="bi bi-clipboard-check"></i> Verificar reporte
                            </a>
                        `;
                        
                        // Añadir al final del popup
                        popup.appendChild(btnContainer);
                    }
                }
            }
        });
    }
    
    // Añadir event listener para cuando se abra un popup
    function setup() {
        console.log("Configurando sistema de detección de popups");
        
        // No utilizamos window.map.on ya que parece no estar disponible
        
        // Utilizar MutationObserver para detectar cambios en el DOM
        const observer = new MutationObserver(function(mutations) {
            let shouldCheckForPopups = false;
            
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                    for (let i = 0; i < mutation.addedNodes.length; i++) {
                        const node = mutation.addedNodes[i];
                        if (node.nodeType === 1) { // Elemento
                            if (node.classList && 
                                (node.classList.contains('leaflet-popup') || 
                                 node.querySelector('.leaflet-popup'))) {
                                shouldCheckForPopups = true;
                                break;
                            }
                        }
                    }
                }
            });
            
            if (shouldCheckForPopups) {
                console.log("Detectado cambio que podría incluir popups");
                setTimeout(addVerifyButton, 100);
            }
        });
        
        // Observar todo el body para detectar cuando se añade un popup
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        // Detectar clics en el documento, que podrían abrir popups
        document.addEventListener('click', function(e) {
            // Esperar un poco para que el popup se pueda abrir
            setTimeout(function() {
                const popups = document.querySelectorAll('.leaflet-popup');
                if (popups.length > 0) {
                    setTimeout(addVerifyButton, 100);
                }
            }, 300);
        });
        
        // También intentar periódicamente por si acaso
        setInterval(addVerifyButton, 2000);
        
        // Ejecutar una vez inicialmente
        setTimeout(addVerifyButton, 1000);
    }
    
    // Ejecutar cuando el DOM esté completamente cargado
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(setup, 500);
        });
    } else {
        setTimeout(setup, 500);
    }
})();