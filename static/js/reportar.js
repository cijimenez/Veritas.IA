window.requestCaptcha = null;
document.addEventListener('DOMContentLoaded', function() {
        // Verificar si se requiere actualización al cargar la página
    if (window.location.search.includes('refresh=true')) {
        loadReports();  // Recargar los reportes
    }
    // Obtener elementos del DOM
    const mapElement = document.getElementById('map');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const newReportBtn = document.getElementById('newReportBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const reportForm = document.getElementById('reportForm');
    const getLocationBtn = document.getElementById('getLocationBtn');
    const locationInfo = document.getElementById('locationInfo');
    const submitBtn = document.getElementById('submitBtn');
    const notification = document.getElementById('notification');
    const captchaContainer = document.getElementById('captcha-container');
    const cooldownContainer = document.getElementById('cooldown-container');
    const cooldownTimer = document.getElementById('cooldown-timer');
    
    // API URL
    const API_URL = '/api';
    
    // Variables globales para el captcha
    window.captchaTextValue = '';
    window.captchaIdValue = '';
    
    // Tipos de reportes y sus colores (debe coincidir con el backend)
    const REPORT_TYPES = {
        'intimidacion': { label: 'Intimidación a votantes', color: 'red', icon: 'exclamation-triangle' },
        'compra_votos': { label: 'Compra de votos', color: 'blue', icon: 'cash-coin' },
        'propaganda_ilegal': { label: 'Propaganda ilegal', color: 'green', icon: 'megaphone' },
        'suplantacion': { label: 'Suplantación de identidad', color: 'purple', icon: 'person-badge' },
        'obstruccion': { label: 'Obstrucción del proceso', color: 'orange', icon: 'x-circle' },
        'destruccion': { label: 'Destrucción de material', color: 'black', icon: 'trash' },
        'violencia': { label: 'Violencia en centro de votación', color: 'darkred', icon: 'exclamation-octagon' },
        'fraude': { label: 'Fraude en conteo', color: 'darkblue', icon: 'calculator' },
        'manipulacion': { label: 'Manipulación de materiales', color: 'darkgreen', icon: 'pencil' },
        'informacion_falsa': { label: 'Información falsa', color: 'gray', icon: 'chat-quote' },
    };
    
    // Variables globales
    let map;
    let markers = [];
    let currentLocation = null;
    let cooldownInterval = null;
    let lastKnownLocation = null; // Añadir esta variable global
    // Variables globales para el captcha
    window.captchaTextValue = '';
    window.captchaIdValue = '';
    
    // Inicializar mapa
    function initMap() {
        // Coordenadas de Ecuador (Quito)
        const ecuadorPosition = [-0.1807, -78.4678];
        
        // Crear mapa con opciones mejoradas
        map = L.map('map', {
            center: ecuadorPosition,
            zoom: 7,
            zoomControl: true,
            attributionControl: true,
        });
        
        // Añadir capa base más detallada
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 19
        }).addTo(map);
        
        // Añadir control de ubicación (estilo Google Maps)
        L.control.locate({
            position: 'bottomright',
            icon: 'bi bi-geo-alt',
            iconLoading: 'bi bi-hourglass',
            strings: {
                title: "Mostrar mi ubicación",
                popup: "Estás dentro de {distance} metros de este punto",
                outsideMapBoundsMsg: "Pareces estar fuera de los límites del mapa"
            },
            locateOptions: {
                enableHighAccuracy: false, // Cambiado a false para mayor velocidad
                timeout: 5000,             // Añadido timeout de 5 segundos
                maximumAge: 60000          // Usar cache de hasta 1 minuto
            },
            onLocationError: function(err) {
                showNotification("Error al obtener ubicación: " + err.message, "error");
            },
            flyTo: true,
            returnToPrevBounds: true
        }).addTo(map);
        
        // Añadir control de escala
        L.control.scale({
            imperial: false,
            position: 'bottomright'
        }).addTo(map);
        
        // Añadir leyenda de tipos de reportes
        const legend = L.control({position: 'bottomleft'});
        legend.onAdd = function (map) {
            const div = L.DomUtil.create('div', 'info legend');
            div.style.backgroundColor = 'rgba(255, 255, 255, 0.8)';
            div.style.padding = '10px';
            div.style.borderRadius = '5px';
            div.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.2)';
            div.style.maxHeight = '200px';
            div.style.overflowY = 'auto';
            
            div.innerHTML = '<h4 style="margin-top: 0; font-size: 14px; margin-bottom: 8px;">Tipos de Incidentes</h4>';
            
            // Añadir cada tipo de reporte a la leyenda
            Object.entries(REPORT_TYPES).forEach(([key, value]) => {
                div.innerHTML += `
                    <div style="display: flex; align-items: center; margin-bottom: 5px;">
                        <span style="background-color: ${value.color}; width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 5px;"></span>
                        <span style="font-size: 12px;">${value.label}</span>
                    </div>
                `;
            });
            
            return div;
        };
        legend.addTo(map);
        
        // Cargar reportes iniciales
        loadReports();
        
        // Actualizar reportes cada 3 minutos
        setInterval(loadReports, 180000);
        
        map.on('locationfound', function(e) {
            // Guardar en variable global
            lastKnownLocation = {
                latitude: e.latlng.lat,
                longitude: e.latlng.lng
            };
            
            // Actualizar formulario automáticamente si está abierto
            if (document.getElementById('sidebar').classList.contains('open')) {
                // Rellenar los campos ocultos
                document.getElementById('latitude').value = lastKnownLocation.latitude;
                document.getElementById('longitude').value = lastKnownLocation.longitude;
                
                // Actualizar el mensaje informativo
                document.getElementById('locationInfo').innerHTML = `
                    <div style="color: #4CAF50;">
                        <i class="bi bi-check-circle"></i> Ubicación obtenida:<br>
                        Latitud: ${lastKnownLocation.latitude.toFixed(6)}<br>
                        Longitud: ${lastKnownLocation.longitude.toFixed(6)}
                    </div>
                `;
                
                // Habilitar botón de envío
                document.getElementById('submitBtn').disabled = false;
                
                // Notificar al usuario
                showNotification('Ubicación actualizada automáticamente', 'success');
            }
            
            // Mostrar marcador en el mapa (código original)
            L.marker(e.latlng).addTo(map)
                .bindPopup('Tu ubicación actual')
                .openPopup();
        });
    }
    
    // Cargar reportes desde la API
    async function loadReports() {
        try {
            // Mostrar pequeña indicación de carga
            const loadingDiv = document.createElement('div');
            loadingDiv.id = 'map-loading';
            loadingDiv.innerHTML = `
                <div style="
                    position: absolute;
                    bottom: 20px;
                    left: 20px;
                    background: rgba(0, 0, 0, 0.7);
                    color: white;
                    padding: 10px 15px;
                    border-radius: 20px;
                    z-index: 1000;
                    font-size: 14px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                ">
                    <div class="spinner-border spinner-border-sm" role="status" style="width: 16px; height: 16px;"></div>
                    Actualizando mapa...
                </div>
            `;
            document.body.appendChild(loadingDiv);
            
            const response = await fetch(`${API_URL}/reports`);
            if (!response.ok) {
                throw new Error('Error al cargar reportes');
            }
            
            const reports = await response.json();
            updateMap(reports);
            
            // Mostrar la cantidad de reportes cargados
            showNotification(`${reports.length} reportes cargados en el mapa`, 'success');
            
            // Eliminar indicador de carga
            document.getElementById('map-loading')?.remove();
        } catch (error) {
            showNotification('Error al cargar reportes: ' + error.message, 'error');
            console.error('Error:', error);
            document.getElementById('map-loading')?.remove();
        }
    }
    
    // Actualizar mapa con reportes
    function updateMap(reports) {
        // Limpiar marcadores actuales
        console.log("UpdateMap ejecutándose con", reports.length, "reportes");
        markers.forEach(marker => map.removeLayer(marker));
        markers = [];
        
        // Añadir nuevos marcadores
        reports.forEach(report => {
            // Crear icono personalizado según el tipo de reporte
            const color = report.color || 'red';
            const reportType = report.report_type || 'informacion_falsa';
            const iconClass = REPORT_TYPES[reportType]?.icon || 'exclamation-circle';
            
            // Usar un ícono más visible y distintivo con el ícono de Bootstrap
            const icon = L.divIcon({
                className: 'custom-report-icon',
                html: `
                    <div style="
                        background-color: ${color}; 
                        width: 28px; 
                        height: 28px; 
                        border-radius: 50%; 
                        border: 3px solid white; 
                        box-shadow: 0 0 15px rgba(0,0,0,0.5);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                        font-size: 14px;
                    ">
                        <i class="bi bi-${iconClass}"></i>
                    </div>
                `,
                iconSize: [36, 36],
                iconAnchor: [18, 18]
            });
            
            // Crear marcador
            const marker = L.marker([report.latitude, report.longitude], { icon }).addTo(map);
            
            // Crear contenido del popup
            const reportTypeName = REPORT_TYPES[report.report_type]?.label || report.report_type;
            const createdAt = new Date(report.created_at).toLocaleString('es-ES');
            
            // En la función updateMap, dentro del template de popupContent
            const popupContent = `
                <div style="min-width: 250px;">
                    <h4 style="margin-bottom: 10px; color: #333; font-weight: 600;">
                        <span style="display: inline-block; width: 10px; height: 10px; background-color: ${color}; border-radius: 50%; margin-right: 8px;"></span>
                        ${reportTypeName}
                    </h4>
                    <p style="margin-bottom: 10px; color: #555;">${report.description}</p>
                    <small style="color: #777;">Reportado: ${createdAt}</small>
                    
                    <!-- Indicador de verificación si existe -->
                    ${report.verified ? 
                    `<div style="margin-top: 10px; padding: 5px; background-color: ${report.verified_status === 'true' ? '#d4edda' : '#f8d7da'}; border-radius: 5px; text-align: center;">
                        <i class="bi bi-${report.verified_status === 'true' ? 'check-circle-fill' : 'x-circle-fill'}" 
                        style="color: ${report.verified_status === 'true' ? 'green' : 'red'}; margin-right: 5px;"></i>
                        <span style="font-weight: 500; color: ${report.verified_status === 'true' ? 'green' : 'red'};">
                        ${report.verified_status === 'true' ? 'Verificado como verdadero' : 'Verificado como falso'}
                        </span>
                        <a href="/verification_details.html?report_id=${report.id}" style="display: block; margin-top: 5px; font-size: 0.8rem;">Ver detalles</a>
                    </div>` 
                    : ''}
                    
                    <div style="margin-top: 15px; display: flex; justify-content: space-between; flex-wrap: wrap;">
                        <button class="vote-btn" data-report-id="${report.id}" data-vote-type="like" style="background: #f0f0f0; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; display: flex; align-items: center; color: #333; margin-bottom: 5px;">
                            <i class="bi bi-hand-thumbs-up" style="margin-right: 5px;"></i> ${report.likes}
                        </button>
                        <button class="vote-btn" data-report-id="${report.id}" data-vote-type="dislike" style="background: #f0f0f0; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; display: flex; align-items: center; color: #333; margin-bottom: 5px;">
                            <i class="bi bi-hand-thumbs-down" style="margin-right: 5px;"></i> ${report.dislikes}
                        </button>
                    </div>
                    
                    <!-- Único botón de verificación -->
                    <a href="/verify_report.html?report_id=${report.id}" class="btn btn-primary" style="display: block; width: 100%; text-align: center; margin-top: 8px; padding: 5px; text-decoration: none;">
                        <i class="bi bi-clipboard-check"></i> Verificar reporte
                    </a>
                </div>
            `;
            
            // Añadir popup al marcador
            marker.bindPopup(popupContent);
            
            // Añadir evento de clic al popup para los botones de voto
            marker.on('popupopen', () => {
                document.querySelectorAll('.vote-btn').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const reportId = e.currentTarget.getAttribute('data-report-id');
                        const voteType = e.currentTarget.getAttribute('data-vote-type');
                        await voteReport(reportId, voteType);
                    });
                });
            });
            
            // Guardar referencia al marcador
            markers.push(marker);
        });
    }
    
    // Votar en un reporte
    async function voteReport(reportId, voteType) {
        try {
            const response = await fetch(`${API_URL}/reports/${reportId}/vote`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ vote_type: voteType }),
            });
            
            if (!response.ok) {
                throw new Error('Error al votar');
            }
            
            const updatedReport = await response.json();
            showNotification('Voto registrado correctamente', 'success');
            
            // Actualizar solo los votos en el popup actual sin recargar todo
            const popup = document.querySelector('.leaflet-popup-content');
            if (popup) {
                const likeBtn = popup.querySelector('[data-vote-type="like"]');
                const dislikeBtn = popup.querySelector('[data-vote-type="dislike"]');
                
                if (likeBtn && dislikeBtn) {
                    likeBtn.innerHTML = `<i class="bi bi-hand-thumbs-up" style="margin-right: 5px;"></i> ${updatedReport.likes}`;
                    dislikeBtn.innerHTML = `<i class="bi bi-hand-thumbs-down" style="margin-right: 5px;"></i> ${updatedReport.dislikes}`;
                }
            }
        } catch (error) {
            showNotification('Error al votar: ' + error.message, 'error');
            console.error('Error:', error);
        }
    }
    
    // Función para mostrar los datos que se están enviando (para depuración)
    function debugFormData(data) {
        console.log("=== DATOS DEL FORMULARIO ===");
        console.log("- report_type:", data.report_type);
        console.log("- description:", data.description);
        console.log("- latitude:", data.latitude);
        console.log("- longitude:", data.longitude);
        console.log("- captcha_answer:", data.captcha_answer);
        console.log("- captcha_hash:", data.captcha_hash);
        console.log("=========================");
    }
    
    // Solicitar un nuevo CAPTCHA
    async function requestCaptcha() {
        console.log("Solicitando CAPTCHA con método directo");
        
        try {
            // Paso 1: Solicitar CAPTCHA del servidor
            const response = await fetch('/api/captcha');
            if (!response.ok) {
                throw new Error(`Error ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log("CAPTCHA obtenido:", data);
            
            // Guardar en variables globales para uso posterior
            window.captchaTextValue = data.captcha_text;
            window.captchaIdValue = data.captcha_id;
            
            // Paso 2: Obtener elementos del DOM
            const captchaContainer = document.getElementById('captcha-container');
            const captchaHash = document.getElementById('captcha-hash');
            
            if (!captchaContainer || !captchaHash) {
                console.error("No se encontraron elementos básicos del CAPTCHA");
                return false;
            }
            
            // Paso 3: Mostrar el contenedor
            captchaContainer.style.display = 'block';
            captchaContainer.style.visibility = 'visible';
            captchaContainer.style.opacity = '1';
            
            // Paso 4: Guardar el hash
            captchaHash.value = data.captcha_id;
            
            // Paso 5: Método directo - Crear un nuevo elemento para el texto del CAPTCHA
            // Primero eliminar el anterior si existe
            const oldText = document.getElementById('captcha-text');
            if (oldText && oldText.parentNode) {
                oldText.parentNode.removeChild(oldText);
            }
            
            // Crear un elemento completamente nuevo
            const captchaDiv = document.createElement('div');
            captchaDiv.id = 'captcha-text';
            
            // Aplicar estilos críticos directamente
            Object.assign(captchaDiv.style, {
                fontFamily: 'monospace',
                fontSize: '1.8rem',
                letterSpacing: '5px',
                margin: '12px 0',
                padding: '12px 15px',
                backgroundColor: 'rgba(0, 0, 0, 0.5)',
                borderRadius: '6px',
                display: 'inline-block',
                color: 'white',
                cursor: 'pointer',
                textShadow: '1px 1px 2px rgba(0, 0, 0, 0.5)'
            });
            
            // Asignar el texto del CAPTCHA
            captchaDiv.textContent = data.captcha_text;
            
            // Encontrar donde insertar el nuevo elemento
            // Opción 1: Después del párrafo de instrucción
            let inserted = false;
            const instructions = Array.from(captchaContainer.querySelectorAll('p')).find(p => 
                p.textContent.includes('Ingresa') || p.textContent.includes('código')
            );
            
            if (instructions) {
                instructions.insertAdjacentElement('afterend', captchaDiv);
                inserted = true;
            }
            
            // Opción 2: Antes del campo de entrada
            if (!inserted) {
                const inputField = document.getElementById('captcha-answer');
                if (inputField) {
                    inputField.insertAdjacentElement('beforebegin', captchaDiv);
                    inserted = true;
                }
            }
            
            // Opción 3: Como último recurso, añadirlo al contenedor
            if (!inserted) {
                captchaContainer.appendChild(captchaDiv);
            }
            
            // Paso 6: Añadir evento click para refrescar
            captchaDiv.addEventListener('click', function() {
                requestCaptcha();
            });
            
            console.log("CAPTCHA creado y mostrado con método directo");
            
            // Paso 7: Verificación adicional después de un breve retraso
            setTimeout(() => {
                const captchaText = document.getElementById('captcha-text');
                if (!captchaText || !captchaText.textContent || captchaText.textContent.trim() === '') {
                    console.log("CAPTCHA no visible después de timeout, intentando de nuevo con insertCaptchaText");
                    insertCaptchaText(window.captchaTextValue);
                }
            }, 500);
            
            return true;
        } catch (error) {
            console.error('Error al solicitar CAPTCHA:', error);
            showNotification('No se pudo obtener el CAPTCHA. Intenta de nuevo más tarde.', 'error');
            return false;
        }
    }

    window.requestCaptcha = requestCaptcha;
    
    // Función para insertar directamente el texto del captcha (puede ser llamada desde el botón de ayuda)
    function insertCaptchaText(text) {
        console.log("Insertando texto del CAPTCHA directamente:", text);
        
        if (!text) {
            console.warn("Sin texto para insertar en CAPTCHA");
            return false;
        }
        
        // Eliminar elemento antiguo si existe
        const oldText = document.getElementById('captcha-text');
        if (oldText && oldText.parentNode) {
            oldText.parentNode.removeChild(oldText);
        }
        
        // Crear nuevo elemento
        const textDiv = document.createElement('div');
        textDiv.id = 'captcha-text';
        textDiv.textContent = text;
        
        // Aplicar estilos inline
        Object.assign(textDiv.style, {
            fontFamily: 'monospace',
            fontSize: '1.8rem',
            letterSpacing: '5px',
            margin: '12px 0',
            padding: '12px 15px',
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            borderRadius: '6px',
            display: 'inline-block',
            color: 'white',
            cursor: 'pointer',
            textShadow: '1px 1px 2px rgba(0, 0, 0, 0.5)'
        });
        
        // Buscar dónde insertar
        const container = document.getElementById('captcha-container');
        const answerInput = document.getElementById('captcha-answer');
        
        // Encontrar mejor lugar para insertar
        let inserted = false;
        if (container) {
            const instructions = Array.from(container.querySelectorAll('p')).find(p => 
                p.textContent.includes('Ingresa') || p.textContent.includes('código')
            );
            
            if (instructions) {
                instructions.insertAdjacentElement('afterend', textDiv);
                inserted = true;
            } else if (answerInput) {
                answerInput.insertAdjacentElement('beforebegin', textDiv);
                inserted = true;
            } else {
                container.appendChild(textDiv);
                inserted = true;
            }
        }
        
        if (!inserted) {
            console.error("No se pudo insertar el texto del CAPTCHA");
            return false;
        }
        
        // Añadir evento para refrescar (usando requestCaptcha si está disponible, o nulo si no)
        const requestCaptchaFn = window.requestCaptcha || function() {
            console.log("Función requestCaptcha no disponible");
        };
        
        textDiv.addEventListener('click', () => {
            if (typeof requestCaptchaFn === 'function') {
                requestCaptchaFn();
            }
        });
        
        return true;
    }
    
    // Función para detectar interacciones de usuario y mostrar CAPTCHA si es necesario
    function addCaptchaUserInteractionDetection() {
        const captchaContainer = document.getElementById('captcha-container');
        if (!captchaContainer) return;
        
        // Detectamos si ha habido alguna interacción del usuario
        let userInteracted = false;
        
        // Eventos a monitorear
        const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
        
        // Función que maneja los eventos
        const interactionHandler = () => {
            if (userInteracted) return; // Solo ejecutar una vez
            userInteracted = true;
            
            console.log("Interacción de usuario detectada, verificando CAPTCHA...");
            
            // Comprobar si el captcha está visible y tiene texto
            const captchaText = document.getElementById('captcha-text');
            if (!captchaText || !captchaText.textContent || captchaText.textContent.trim() === '') {
                console.log("CAPTCHA no visible o sin texto después de interacción, intentando mostrar...");
                
                // Si ya tenemos el valor del CAPTCHA, usarlo directamente
                if (window.captchaTextValue) {
                    insertCaptchaText(window.captchaTextValue);
                } else {
                    requestCaptcha();
                }
            }
            
            // Eliminar eventos una vez detectada la interacción
            events.forEach(event => {
                document.removeEventListener(event, interactionHandler);
            });
        };
        
        // Añadir listeners para cada tipo de evento
        events.forEach(event => {
            document.addEventListener(event, interactionHandler);
        });
        
        // También eliminamos los listeners después de 10 segundos
        setTimeout(() => {
            if (!userInteracted) {
                events.forEach(event => {
                    document.removeEventListener(event, interactionHandler);
                });
            }
        }, 10000);
    }
    
    // Verificar si el usuario puede enviar un nuevo reporte o está en cooldown
    async function checkReportStatus() {
        console.log("Verificando estado de reporte...");
        try {
            const response = await fetch(`${API_URL}/report_status`);
            if (!response.ok) {
                throw new Error('Error al verificar estado');
            }
            
            const data = await response.json();
            console.log("Estado de reporte:", data);
            
            if (!data.can_report) {
                // Configurar y mostrar el temporizador
                startCooldownTimer(data.cooldown_remaining);
                return false;
            }
            
            // Ocultar temporizador si está visible
            if (cooldownContainer) {
                cooldownContainer.style.display = 'none';
            }
            return true;
        } catch (error) {
            console.error('Error al verificar estado:', error);
            return true; // En caso de error, permitimos el envío
        }
    }
    
    // Iniciar el temporizador de cooldown
    function startCooldownTimer(seconds) {
        console.log("Iniciando temporizador de espera de", seconds, "segundos");
        
        // Detener temporizador existente si hay uno
        if (cooldownInterval) {
            clearInterval(cooldownInterval);
        }
        
        let remainingTime = seconds; // Variable local en lugar de modificar cooldownTimer
        
        // Mostrar el contenedor del temporizador
        const timerContainer = document.getElementById('cooldown-container');
        const timerDisplay = document.getElementById('cooldown-timer');
        const submitBtn = document.getElementById('submitBtn');
        
        if (timerContainer && timerDisplay && submitBtn) {
            timerContainer.style.display = 'block';
            submitBtn.disabled = true;
            
            // Actualizar el temporizador cada segundo
            timerDisplay.innerText = formatTime(remainingTime);
            
            cooldownInterval = setInterval(() => {
                remainingTime--; // Usar remainingTime en lugar de cooldownTimer
                timerDisplay.innerText = formatTime(remainingTime);
                
                if (remainingTime <= 0) {
                    clearInterval(cooldownInterval);
                    timerContainer.style.display = 'none';
                    submitBtn.disabled = false;
                    
                    // Solicitar nuevo CAPTCHA
                    requestCaptcha();
                }
            }, 1000);
        } else {
            console.error("No se encontraron elementos necesarios para el temporizador");
        }
    }
    
    // Formatear segundos como MM:SS
    function formatTime(seconds) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    
    // Crear un nuevo reporte
    async function createReport(reportData) {
        try {
            // Depurar datos antes del envío
            debugFormData(reportData);
            
            // Verificar que los datos del CAPTCHA estén presentes
            if (!reportData.captcha_answer || !reportData.captcha_hash) {
                console.error("Datos de CAPTCHA faltantes");
                const captchaAnswer = document.getElementById('captcha-answer');
                const captchaHash = document.getElementById('captcha-hash');
                
                console.log("Elemento captcha-answer:", captchaAnswer);
                console.log("Valor actual:", captchaAnswer?.value);
                console.log("Elemento captcha-hash:", captchaHash);
                console.log("Valor actual:", captchaHash?.value);
                
                showNotification('Error: Datos de CAPTCHA incompletos. Intenta de nuevo.', 'error');
                requestCaptcha(); // Solicitar un nuevo CAPTCHA
                throw new Error('Datos de CAPTCHA incompletos');
            }
            
            // Intentar el envío
            const response = await fetch(`${API_URL}/reports`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(reportData),
            });
            
            // Mostrar respuesta completa para depuración
            const result = await response.json();
            console.log("Respuesta del servidor:", result);
            
            if (!response.ok) {
                throw new Error(result.error || 'Error al crear reporte');
            }
            
            showNotification('Reporte creado exitosamente', 'success');
            
            // Resto del código para crear el reporte exitosamente...
            addReportToMap(result);
            map.setView([result.latitude, result.longitude], 15);
            toggleSidebar(false);
            startCooldownTimer(300);
            
            return result;
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
            console.error('Error detallado:', error);
            throw error;
        }
    }
    
    // Añadir un solo reporte al mapa (para actualización instantánea)
    // Añadir un solo reporte al mapa (para actualización instantánea)
    function addReportToMap(report) {
        const color = report.color || 'red';
        const reportType = report.report_type || 'informacion_falsa';
        const iconClass = REPORT_TYPES[reportType]?.icon || 'exclamation-circle';
        
        // Usar un ícono más visible y distintivo con el ícono de Bootstrap
        const icon = L.divIcon({
            className: 'custom-report-icon',
            html: `
                <div style="
                    background-color: ${color}; 
                    width: 32px; 
                    height: 32px; 
                    border-radius: 50%; 
                    border: 3px solid white; 
                    box-shadow: 0 0 15px rgba(0,0,0,0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                    font-size: 16px;
                    animation: pulse 1.5s infinite;
                ">
                    <i class="bi bi-${iconClass}"></i>
                </div>
                <style>
                @keyframes pulse {
                    0% { transform: scale(1); }
                    50% { transform: scale(1.3); }
                    100% { transform: scale(1); }
                }
                </style>
            `,
            iconSize: [40, 40],
            iconAnchor: [20, 20]
        });
        
        // Crear marcador
        const marker = L.marker([report.latitude, report.longitude], { icon }).addTo(map);
        
        // Crear contenido del popup
        const reportTypeName = REPORT_TYPES[report.report_type]?.label || report.report_type;
        const createdAt = new Date(report.created_at).toLocaleString('es-ES');
        
        const popupContent = `
            <div style="min-width: 250px;">
                <h4 style="margin-bottom: 10px; color: #333; font-weight: 600;">
                    <span style="display: inline-block; width: 10px; height: 10px; background-color: ${color}; border-radius: 50%; margin-right: 8px;"></span>
                    ${reportTypeName}
                </h4>
                <p style="margin-bottom: 10px; color: #555;">${report.description}</p>
                <small style="color: #777;">Reportado: ${createdAt}</small>
                
                <!-- Indicador de verificación si existe -->
                ${report.verified ? 
                `<div style="margin-top: 10px; padding: 5px; background-color: ${report.verified_status === 'true' ? '#d4edda' : '#f8d7da'}; border-radius: 5px; text-align: center;">
                    <i class="bi bi-${report.verified_status === 'true' ? 'check-circle-fill' : 'x-circle-fill'}" 
                    style="color: ${report.verified_status === 'true' ? 'green' : 'red'}; margin-right: 5px;"></i>
                    <span style="font-weight: 500; color: ${report.verified_status === 'true' ? 'green' : 'red'};">
                    ${report.verified_status === 'true' ? 'Verificado como verdadero' : 'Verificado como falso'}
                    </span>
                    <a href="/verification_details.html?report_id=${report.id}" style="display: block; margin-top: 5px; font-size: 0.8rem;">Ver detalles</a>
                </div>` 
                : ''}
                
                <div style="margin-top: 15px; display: flex; justify-content: space-between; flex-wrap: wrap;">
                    <button class="vote-btn" data-report-id="${report.id}" data-vote-type="like" style="background: #f0f0f0; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; display: flex; align-items: center; color: #333; margin-bottom: 5px;">
                        <i class="bi bi-hand-thumbs-up" style="margin-right: 5px;"></i> ${report.likes}
                    </button>
                    <button class="vote-btn" data-report-id="${report.id}" data-vote-type="dislike" style="background: #f0f0f0; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; display: flex; align-items: center; color: #333; margin-bottom: 5px;">
                        <i class="bi bi-hand-thumbs-down" style="margin-right: 5px;"></i> ${report.dislikes}
                    </button>
                    <a href="/verify_report.html?report_id=${report.id}" class="btn btn-primary" style="display: block; width: 100%; text-align: center; margin-top: 8px; padding: 5px; text-decoration: none; background-color: #007bff; color: white; border-radius: 5px;">
                        <i class="bi bi-clipboard-check"></i> Verificar reporte
                    </a>
                </div>
            </div>
        `;
        
        // Añadir popup al marcador
        marker.bindPopup(popupContent);
        
        // Añadir evento de clic al popup para los botones de voto
        marker.on('popupopen', () => {
            document.querySelectorAll('.vote-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const reportId = e.currentTarget.getAttribute('data-report-id');
                    const voteType = e.currentTarget.getAttribute('data-vote-type');
                    await voteReport(reportId, voteType);
                });
            });
        });
        
        // Abrir el popup automáticamente para el nuevo reporte
        marker.openPopup();
        
        // Guardar referencia al marcador
        markers.push(marker);
    }
    
    // Obtener ubicación del usuario
    function getUserLocation() {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(new Error('Tu navegador no soporta geolocalización'));
                return;
            }
            
            navigator.geolocation.getCurrentPosition(
                position => {
                    const location = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                    };
                    resolve(location);
                },
                error => {
                    reject(error);
                },
                { 
                    enableHighAccuracy: false, // Cambiado a false para mayor velocidad
                    timeout: 5000,             // Añadido timeout de 5 segundos
                    maximumAge: 60000          // Usar cache de hasta 1 minuto
                }
            );
        });
    }
    
    // Mostrar notificación
    function showNotification(message, type) {
        notification.textContent = message;
        notification.className = `notification ${type}`;
        notification.style.display = 'block';
        
        setTimeout(() => {
            notification.style.display = 'none';
        }, 5000);
    }
    
    // Alternar sidebar
    function toggleSidebar(show) {
        if (show) {
            // Mostrar sidebar primero
            sidebar.classList.add('open');
            sidebarOverlay.classList.add('open');
            
            // Pequeño retraso para asegurar que el DOM está listo
            setTimeout(async () => {
                // Verificar si el usuario puede reportar
                const canReport = await checkReportStatus();
                
                if (canReport) {
                    console.log("Usuario puede reportar, solicitando CAPTCHA...");
                    
                    // Forzar visibilidad del contenedor de CAPTCHA
                    const captchaContainer = document.getElementById('captcha-container');
                    if (captchaContainer) {
                        captchaContainer.style.display = 'block';
                        captchaContainer.style.visibility = 'visible';
                        captchaContainer.style.opacity = '1';
                    }
                    
                    // Solicitar CAPTCHA e iniciar detección de interacción
                    const captchaSuccess = await requestCaptcha();
                    
                    // Forzar la visualización del captcha inmediatamente
                    if (window.captchaTextValue && !document.getElementById('captcha-text')) {
                        console.log("Forzando visualización del captcha:", window.captchaTextValue);
                        insertCaptchaText(window.captchaTextValue);
                    }
                    
                    // Usar setTimeout con diferentes tiempos para maximizar posibilidades
                    const tryDisplayCaptcha = () => {
                        if (!document.getElementById('captcha-text') && window.captchaTextValue) {
                            console.log("Nuevo intento de mostrar captcha:", window.captchaTextValue);
                            insertCaptchaText(window.captchaTextValue);
                        }
                    };
                    
                    // Intentar mostrar el captcha en diferentes momentos
                    setTimeout(tryDisplayCaptcha, 300);
                    setTimeout(tryDisplayCaptcha, 800);
                    setTimeout(tryDisplayCaptcha, 1500);
                    
                    // También activar detección de interacción
                    addCaptchaUserInteractionDetection();
                    
                } else {
                    console.log("Usuario en cooldown, no se solicita CAPTCHA");
                }
            }, 100);
        } else {
            // Ocultar sidebar
            sidebar.classList.remove('open');
            sidebarOverlay.classList.remove('open');
            
            // Limpiar formulario
            reportForm.reset();
            locationInfo.innerHTML = '';
            currentLocation = null;
            submitBtn.disabled = true;
            
            // Ocultar CAPTCHA
            const captchaContainer = document.getElementById('captcha-container');
            if (captchaContainer) {
                captchaContainer.style.display = 'none';
            }
        }
    }
    
    // Inicializar mapa
    initMap();
    
    // Event Listeners
    // Manejar clic en el botón de nuevo reporte
    newReportBtn.addEventListener('click', () => {
        toggleSidebar(true);
    });
    
    // Manejar clic en el overlay para cerrar sidebar
    sidebarOverlay.addEventListener('click', () => {
        toggleSidebar(false);
    });
    
    // Manejar clic en el CAPTCHA para refrescarlo
    if (document.getElementById('captcha-text')) {
        document.getElementById('captcha-text').addEventListener('click', () => {
            requestCaptcha();
        });
    }

    // Añadir evento para el botón de mostrar captcha
    const showCaptchaBtn = document.getElementById('show-captcha-btn');
    if (showCaptchaBtn) {
        showCaptchaBtn.addEventListener('click', function() {
            if (window.captchaTextValue) {
                insertCaptchaText(window.captchaTextValue);
            } else {
                requestCaptcha();
            }
        });
    }
    
    // Manejar clic en el botón de obtener ubicación
    getLocationBtn.addEventListener('click', async () => {
        // Mostrar animación de carga más visible
        locationInfo.innerHTML = `
            <div style="text-align: center; color: white;">
                <div class="spinner-border text-light" role="status" style="width: 1.5rem; height: 1.5rem;"></div>
                <div style="margin-top: 8px;">Obteniendo ubicación...</div>
                <div style="font-size: 0.8rem; margin-top: 4px;">Esto puede tardar unos segundos</div>
            </div>
        `;
        
        // Si ya tenemos la ubicación del mapa, usarla inmediatamente
        if (lastKnownLocation) {
            setTimeout(() => {
                currentLocation = lastKnownLocation;
                
                // Rellenar los campos ocultos
                document.getElementById('latitude').value = lastKnownLocation.latitude;
                document.getElementById('longitude').value = lastKnownLocation.longitude;
                
                locationInfo.innerHTML = `
                    <div style="color: #4CAF50;">
                        <i class="bi bi-check-circle"></i> Ubicación obtenida:<br>
                        Latitud: ${lastKnownLocation.latitude.toFixed(6)}<br>
                        Longitud: ${lastKnownLocation.longitude.toFixed(6)}
                    </div>
                `;
                
                // Habilitar botón de envío si no está en cooldown
                if (cooldownContainer.style.display !== 'block') {
                    submitBtn.disabled = false;
                }
            }, 300); // Pequeño retraso para mostrar la animación
            return;
        }
        
        // Si no hay ubicación previa, solicitar una nueva
        try {
            const location = await getUserLocation();
            currentLocation = location;
            lastKnownLocation = location; // Guardar también en la variable global
            
            locationInfo.innerHTML = `
                <div style="color: #4CAF50;">
                    <i class="bi bi-check-circle"></i> Ubicación obtenida:<br>
                    Latitud: ${location.latitude.toFixed(6)}<br>
                    Longitud: ${location.longitude.toFixed(6)}
                </div>
            `;
            
            // Habilitar botón de envío si no está en cooldown
            if (cooldownContainer.style.display !== 'block') {
                submitBtn.disabled = false;
            }
        } catch (error) {
            locationInfo.innerHTML = `
                <div style="color: #F44336;">
                    <i class="bi bi-exclamation-triangle"></i> Error: ${error.message || 'No se pudo obtener tu ubicación'}
                </div>
            `;
            
            // Mantener botón deshabilitado
            submitBtn.disabled = true;
        }
    });
    
    // Sobrescribir la función de envío del formulario
    reportForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        console.log("Formulario enviado - iniciando validación manual");
        
        if (!currentLocation) {
            showNotification('Debes obtener tu ubicación primero', 'error');
            return;
        }
        
        // Obtener valores del formulario directamente de los elementos DOM
        const reportType = document.getElementById('reportType').value;
        const description = document.getElementById('description').value;
        
        // Obtener datos del CAPTCHA directamente
        const captchaAnswer = document.getElementById('captcha-answer').value.trim();
        const captchaHash = document.getElementById('captcha-hash').value;
        
        console.log("CAPTCHA answer:", captchaAnswer);
        console.log("CAPTCHA hash:", captchaHash);
        
        if (!reportType || !description) {
            showNotification('Todos los campos son obligatorios', 'error');
            return;
        }
        
        if (!captchaAnswer) {
            showNotification('Debes completar el CAPTCHA', 'error');
            return;
        }
        
        // Deshabilitar botón durante el envío
        submitBtn.disabled = true;
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Enviando...';
        
        try {
            const reportData = {
                report_type: reportType,
                description: description,
                latitude: currentLocation.latitude,
                longitude: currentLocation.longitude,
                captcha_answer: captchaAnswer,
                captcha_hash: captchaHash
            };
            
            await createReport(reportData);
            
            // Resetear formulario
            reportForm.reset();
            locationInfo.innerHTML = '';
            currentLocation = null;
        } catch (error) {
            console.error('Error en envío del formulario:', error);
            
            // Si el error menciona CAPTCHA, solicitar uno nuevo
            if (error.message && error.message.includes('CAPTCHA')) {
                console.log("Solicitando nuevo CAPTCHA debido a error");
                requestCaptcha();
            }
        } finally {
            // Restaurar botón
            submitBtn.disabled = true;
            submitBtn.innerHTML = originalBtnText;
        }
    });
    
    // Manejar clic en el botón de actualizar
    refreshBtn.addEventListener('click', () => {
        loadReports();
        showNotification('Reportes actualizados', 'success');
    });
    
    console.log("=== DEPURACIÓN DEL CAPTCHA ACTIVADA ===");
    console.log("Comprobando elementos del CAPTCHA:");
    console.log("- captcha-container:", document.getElementById('captcha-container'));
    console.log("- captcha-text:", document.getElementById('captcha-text'));
    console.log("- captcha-hash:", document.getElementById('captcha-hash'));
    console.log("- captcha-answer:", document.getElementById('captcha-answer'));
    
    // Auto-iniciar la verificación del captcha al cargar la página
    setTimeout(() => {
        // Verificar si el sidebar está abierto (posiblemente desde una carga de página o refresco)
        if (sidebar.classList.contains('open')) {
            console.log("Sidebar ya abierto al iniciar, verificando CAPTCHA...");
            requestCaptcha();
            addCaptchaUserInteractionDetection();
        }
    }, 1000);



    // Auto-iniciar la visualización al abrir el formulario
    newReportBtn.addEventListener('click', function() {
        // Asegurarse de que se muestra el captcha después de abrir el sidebar
        setTimeout(function() {
            if (window.captchaTextValue) {
                console.log("Auto-mostrando captcha después de clic en nuevo reporte");
                insertCaptchaText(window.captchaTextValue);
            } else {
                requestCaptcha().then(() => {
                    setTimeout(() => {
                        if (window.captchaTextValue) {
                            insertCaptchaText(window.captchaTextValue);
                        }
                    }, 500);
                });
            }
        }, 600);
    });

});