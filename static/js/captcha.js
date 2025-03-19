// Variables globales
let cooldownTimer = null;
let cooldownInterval = null;

// Función para obtener un nuevo CAPTCHA
async function requestCaptcha() {
  console.log("Solicitando CAPTCHA...");
  try {
    const response = await fetch('/api/captcha');
    if (!response.ok) {
      throw new Error('Error al solicitar CAPTCHA');
    }
    
    const data = await response.json();
    console.log("CAPTCHA recibido:", data);
    
    // Mostrar el CAPTCHA en la interfaz
    const captchaText = document.getElementById('captcha-text');
    const captchaHash = document.getElementById('captcha-hash');
    const captchaContainer = document.getElementById('captcha-container');
    
    if (captchaText && captchaHash && captchaContainer) {
      captchaText.innerText = data.captcha_text;
      captchaHash.value = data.captcha_id;
      captchaContainer.style.display = 'block';
      console.log("CAPTCHA mostrado correctamente");
    } else {
      console.error("No se encontraron los elementos del CAPTCHA en el DOM");
    }
    
    return true;
  } catch (error) {
    console.error('Error al solicitar CAPTCHA:', error);
    if (typeof showNotification === 'function') {
      showNotification('No se pudo obtener el CAPTCHA. Intenta de nuevo más tarde.', 'error');
    } else {
      alert('No se pudo obtener el CAPTCHA. Intenta de nuevo más tarde.');
    }
    return false;
  }
}

// Función para verificar el estado del cooldown
async function checkReportStatus() {
  console.log("Verificando estado de reporte...");
  try {
    const response = await fetch('/api/report_status');
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
    
    // Ocultar el temporizador si está visible
    const cooldownContainer = document.getElementById('cooldown-container');
    if (cooldownContainer) {
      cooldownContainer.style.display = 'none';
    }
    
    return true;
  } catch (error) {
    console.error('Error al verificar estado:', error);
    return true; // En caso de error, permitimos el envío
  }
}

// Función para iniciar el temporizador de espera
function startCooldownTimer(seconds) {
  console.log("Iniciando temporizador de espera de", seconds, "segundos");
  
  // Detener temporizador existente si hay uno
  if (cooldownInterval) {
    clearInterval(cooldownInterval);
  }
  
  cooldownTimer = seconds;
  
  // Mostrar el contenedor del temporizador
  const timerContainer = document.getElementById('cooldown-container');
  const timerDisplay = document.getElementById('cooldown-timer');
  const submitBtn = document.getElementById('submitBtn');
  
  if (timerContainer && timerDisplay && submitBtn) {
    timerContainer.style.display = 'block';
    submitBtn.disabled = true;
    
    // Actualizar el temporizador cada segundo
    timerDisplay.innerText = formatTime(cooldownTimer);
    
    cooldownInterval = setInterval(() => {
      cooldownTimer--;
      timerDisplay.innerText = formatTime(cooldownTimer);
      
      if (cooldownTimer <= 0) {
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

// Integrar CAPTCHA con el flujo existente
document.addEventListener('DOMContentLoaded', function() {
  console.log("Inicializando script de CAPTCHA");
  
  // Añadir evento para regenerar CAPTCHA al hacer clic en él
  const captchaText = document.getElementById('captcha-text');
  if (captchaText) {
    captchaText.addEventListener('click', function() {
      console.log("Clic en el texto del CAPTCHA - solicitando nuevo CAPTCHA");
      requestCaptcha();
    });
  }
  
  // Integrar con el botón de nuevo reporte
  const newReportBtn = document.getElementById('newReportBtn');
  if (newReportBtn) {
    const originalClickHandler = newReportBtn.onclick;
    
    newReportBtn.addEventListener('click', async function(e) {
      console.log("Botón de nuevo reporte clickeado");
      
      // Verificar estado antes de mostrar el formulario
      const canReport = await checkReportStatus();
      
      if (canReport) {
        console.log("Usuario puede reportar, solicitando CAPTCHA");
        requestCaptcha();
      } else {
        console.log("Usuario en período de espera");
      }
    });
  }
  
  // Integrar con el formulario de reporte
  const reportForm = document.getElementById('reportForm');
  if (reportForm) {
    const originalSubmitHandler = reportForm.onsubmit;
    
    reportForm.addEventListener('submit', async function(event) {
      // Verificar que se haya ingresado una respuesta para el CAPTCHA
      const captchaAnswer = document.getElementById('captcha-answer').value.trim();
      if (!captchaAnswer) {
        event.preventDefault();
        if (typeof showNotification === 'function') {
          showNotification('Por favor, ingresa el código CAPTCHA', 'error');
        } else {
          alert('Por favor, ingresa el código CAPTCHA');
        }
        return false;
      }
      
      // Continuar con el envío normal del formulario
      console.log("CAPTCHA completado, continuando con el envío del formulario");
    });
  }
  
  console.log("Script de CAPTCHA inicializado correctamente");
});