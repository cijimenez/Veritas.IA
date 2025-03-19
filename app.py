import sqlite3
import os
import json
import datetime
import requests
import time
import logging
import sys
import random
import string
import hashlib
import uuid
import jwt
import bcrypt
import re
from functools import wraps
from flask import jsonify, request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from html import escape

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("veritas_app.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("veritas-ia")

# Definir la ruta de la base de datos para compatibilidad con Render
if os.environ.get('RENDER'):
    # Directorio de datos persistentes en Render
    DB_PATH = '/var/data/reports.db'
    # Asegurar que el directorio existe
    os.makedirs('/var/data', exist_ok=True)
else:
    # Para desarrollo local
    DB_PATH = './reports.db'

logger.info(f"Usando base de datos en: {DB_PATH}")

# Agregar clave secreta para JWT
JWT_SECRET = "veritas_ia_journalists_secret_key"  # En producción, esto debería ser una variable de entorno segura

# Configuración de tiempo de expiración del token (24 horas)
JWT_EXPIRATION = 24 * 60 * 60  # en segundos

# Inicializar base de datos
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Crear tabla de reportes con índices para mejor rendimiento
        c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT,
            latitude REAL,
            longitude REAL,
            description TEXT,
            color TEXT,
            created_at TEXT,
            expires_at TEXT,
            likes INTEGER DEFAULT 0,
            dislikes INTEGER DEFAULT 0,
            verified BOOLEAN DEFAULT 0,
            verified_status TEXT,
            verification_id INTEGER
        )
        ''')
        
        # Crear índices para optimizar consultas frecuentes
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_expires ON reports(expires_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reports_location ON reports(latitude, longitude)')
        
        # Tabla de periodistas/comunicadores
        c.execute('''
        CREATE TABLE IF NOT EXISTS journalists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            organization TEXT,
            role TEXT,
            credentials TEXT,
            created_at TEXT,
            last_login TEXT
        )
        ''')
        
        # Tabla de verificaciones
        c.execute('''
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            journalist_id INTEGER NOT NULL,
            verification_status TEXT NOT NULL,
            evidence_url TEXT,
            organization TEXT NOT NULL,
            explanation TEXT NOT NULL,
            sources TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id),
            FOREIGN KEY (journalist_id) REFERENCES journalists(id)
        )
        ''')
        
        # Índices para las nuevas tablas
        c.execute('CREATE INDEX IF NOT EXISTS idx_journalists_email ON journalists(email)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_verifications_report ON verifications(report_id)')
        
        conn.commit()
        conn.close()
        logger.info("Base de datos inicializada correctamente")
    except sqlite3.Error as e:
        logger.error(f"Error al inicializar la base de datos: {e}")


# API Key de Perplexity
PERPLEXITY_API_KEY = "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"

# Comprobamos si la clave de API es válida
def test_perplexity_api():
    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "sonar",  # Cambiamos al modelo básico por si acaso
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say hello in three words."}
        ]
    }
    
    try:
        response = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            print("API de Perplexity funciona correctamente.")
            return True
        else:
            print(f"Error al probar API de Perplexity: {response.status_code}")
            print(f"Respuesta: {response.text}")
            return False
    except Exception as e:
        print(f"Excepción al probar API de Perplexity: {str(e)}")
        return False

# Colores para los tipos de reportes
REPORT_COLORS = {
    'intimidacion': 'red',
    'compra_votos': 'blue',
    'propaganda_ilegal': 'green',
    'suplantacion': 'purple',
    'obstruccion': 'orange',
    'destruccion': 'black',
    'violencia': 'darkred',
    'fraude': 'darkblue',
    'manipulacion': 'darkgreen',
    'informacion_falsa': 'gray',
}

# Constantes para caché
MAX_CACHE_SIZE = 100  # Máximo número de verificaciones en caché
CACHE_EXPIRY = 3600  # Tiempo de expiración de caché en segundos (1 hora)
verification_cache = {}  # Diccionario para almacenar verificaciones en caché

# Constantes para CAPTCHA y bloqueo temporal
CAPTCHA_EXPIRY = 300  # 5 minutos (300 segundos)
captcha_store = {}  # Almacena captchas generados {ip: {captcha, timestamp, solve_timestamp}}
REPORT_COOLDOWN = 300  # Tiempo de espera obligatorio entre reportes (5 minutos)

# Constantes para rate limiting
REQUEST_LIMITS = {
    'reports': {'count': 0, 'reset_time': 0, 'max': 10},  # máximo 10 reportes por minuto
    'verify': {'count': 0, 'reset_time': 0, 'max': 5},    # máximo 5 verificaciones por minuto
    'vote': {'count': 0, 'reset_time': 0, 'max': 20}      # máximo 20 votos por minuto
}
RATE_LIMIT_WINDOW = 60  # segundos

# Decorador para verificar token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Extraer token del encabezado Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Eliminar 'Bearer ' de la cabecera
        
        if not token:
            return jsonify({'error': 'Token no proporcionado'}), 401
            
        try:
            # Decodificar token
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            journalist_id = payload['sub']
            
            # Verificar que el periodista existe
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM journalists WHERE id = ?', (journalist_id,))
            journalist = c.fetchone()
            conn.close()
            
            if not journalist:
                return jsonify({'error': 'Periodista no encontrado'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
            
        return f(journalist_id, *args, **kwargs)
    
    return decorated

# Funciones para el manejo de CAPTCHA
def generate_captcha():
    """Genera un CAPTCHA simple basado en texto."""
    chars = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(chars) for _ in range(6))
    captcha_hash = hashlib.sha256(captcha_text.encode()).hexdigest()
    return captcha_text, captcha_hash

def get_client_ip(handler):
    """Obtiene la IP del cliente, teniendo en cuenta posibles proxies."""
    ip = handler.headers.get('X-Forwarded-For')
    if ip:
        return ip.split(',')[0].strip()
    return handler.client_address[0]

# Handler HTTP personalizado
class RequestHandler(BaseHTTPRequestHandler):
    # Para evitar logs excesivos en consola
    def log_message(self, format, *args):
        logger.info("%s - - [%s] %s" %
                (self.address_string(),
                 self.log_date_time_string(),
                 format % args))
    
    # Establecer cabeceras CORS
    def _set_headers(self, content_type='application/json', status=200):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    # Manejar solicitudes OPTIONS (para CORS)
    def do_OPTIONS(self):
        self._set_headers()
    
    # Comprobar límite de solicitudes
    def _check_rate_limit(self, limit_type):
        # Si ha pasado el tiempo de reset, reiniciar contador
        current_time = time.time()
        if current_time - REQUEST_LIMITS[limit_type]['reset_time'] > RATE_LIMIT_WINDOW:
            REQUEST_LIMITS[limit_type]['count'] = 0
            REQUEST_LIMITS[limit_type]['reset_time'] = current_time
        
        # Incrementar contador
        REQUEST_LIMITS[limit_type]['count'] += 1
        
        # Comprobar si se ha excedido el límite
        if REQUEST_LIMITS[limit_type]['count'] > REQUEST_LIMITS[limit_type]['max']:
            return False
        return True
    
    # Manejar solicitudes GET
    def do_GET(self):
        try:
            url_parts = urlparse(self.path)
            path = url_parts.path
            
            # Nuevo endpoint para solicitar CAPTCHA
            if path == '/api/captcha':
                self._get_captcha()
            # API para obtener reportes
            elif path == '/api/reports':
                self._get_reports()
            # Verificar estado de cooldown
            elif path == '/api/report_status':
                self._get_report_status()
            # Nueva ruta para obtener un reporte específico
            elif path.startswith('/api/reports/') and len(path.split('/')) == 4:
                report_id = int(path.split('/')[3])
                self._get_report(report_id)
            # Nueva ruta para obtener detalles de verificación
            elif path.startswith('/api/verifications/') and len(path.split('/')) == 4:
                report_id = int(path.split('/')[3])
                self._get_verification_details(report_id)
            # Servir archivos estáticos
            elif path == '/' or path == '':
                self._serve_file('static/index.html', 'text/html')
            elif os.path.exists('static' + path):
                # Determinar el tipo de contenido
                if path.endswith('.html'):
                    content_type = 'text/html'
                elif path.endswith('.css'):
                    content_type = 'text/css'
                elif path.endswith('.js'):
                    content_type = 'application/javascript'
                elif path.endswith('.json'):
                    content_type = 'application/json'
                elif path.endswith('.png'):
                    content_type = 'image/png'
                elif path.endswith('.jpg') or path.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                elif path.endswith('.svg'):
                    content_type = 'image/svg+xml'
                elif path.endswith('.ico'):
                    content_type = 'image/x-icon'
                else:
                    content_type = 'application/octet-stream'
                
                self._serve_file('static' + path, content_type)
            else:
                # Si no existe el archivo, servir index.html
                self._serve_file('static/index.html', 'text/html')
        except Exception as e:
            logger.error(f"Error en solicitud GET: {str(e)}")
            self._handle_server_error(str(e))
    
    # Manejar solicitudes POST
    def do_POST(self):
        try:
            url_parts = urlparse(self.path)
            path = url_parts.path
            
            # Leer contenido de la solicitud
            content_length = int(self.headers['Content-Length'])
            if content_length > 1024 * 1024:  # Limitar a 1MB
                self._handle_client_error("Solicitud demasiado grande")
                return
                
            post_data = self.rfile.read(content_length)
            
            # Crear reporte
            if path == '/api/reports':
                # Comprobar límite de reportes
                if not self._check_rate_limit('reports'):
                    self._handle_rate_limit("Demasiados reportes. Por favor, intenta de nuevo más tarde.")
                    return
                self._create_report(post_data)
            # Votar en un reporte
            elif path.startswith('/api/reports/') and '/vote' in path:
                # Comprobar límite de votos
                if not self._check_rate_limit('vote'):
                    self._handle_rate_limit("Demasiados votos. Por favor, intenta de nuevo más tarde.")
                    return
                try:
                    report_id = int(path.split('/')[3])
                    self._vote_report(report_id, post_data)
                except (ValueError, IndexError):
                    self._handle_client_error("ID de reporte inválido")
            # Verificar noticia con Perplexity
            elif path == '/api/verify':
                # Comprobar límite de verificaciones
                if not self._check_rate_limit('verify'):
                    self._handle_rate_limit("Demasiadas verificaciones. Por favor, intenta de nuevo más tarde.")
                    return
                self._verify_news(post_data)
            # Nuevas rutas para autenticación de periodistas
            elif path == '/api/journalists/register':
                self._register_journalist(post_data)
            elif path == '/api/journalists/login':
                self._login_journalist(post_data)
            # Nueva ruta para verificación de reportes
            elif path == '/api/verifications':
                self._create_verification(post_data)
            else:
                self._handle_not_found()
        except Exception as e:
            logger.error(f"Error en solicitud POST: {str(e)}")
            self._handle_server_error(str(e))
    
    # Manejar error 400 (Bad Request)
    def _handle_client_error(self, message):
        self.send_response(400)
        self.end_headers()
        response = {'error': message}
        self.wfile.write(json.dumps(response).encode())
        logger.warning(f"Error del cliente: {message}")
    
    # Manejar error 404 (Not Found)
    def _handle_not_found(self):
        self.send_response(404)
        self.end_headers()
        response = {'error': 'Ruta no encontrada'}
        self.wfile.write(json.dumps(response).encode())
        logger.warning(f"Ruta no encontrada: {self.path}")
    
    # Manejar error 429 (Too Many Requests)
    def _handle_rate_limit(self, message):
        self.send_response(429)
        self.send_header('Retry-After', str(RATE_LIMIT_WINDOW))
        self.end_headers()
        response = {'error': message}
        self.wfile.write(json.dumps(response).encode())
        logger.warning(f"Límite de tasa excedido: {message}")
    
    # Manejar error 500 (Internal Server Error)
    def _handle_server_error(self, message):
        self.send_response(500)
        self.end_headers()
        response = {'error': 'Error interno del servidor'}
        self.wfile.write(json.dumps(response).encode())
        logger.error(f"Error del servidor: {message}")
    
    # Generar y enviar un nuevo CAPTCHA
    def _get_captcha(self):
        """Genera y envía un nuevo CAPTCHA."""
        try:
            client_ip = get_client_ip(self)
            captcha_text, captcha_hash = generate_captcha()
            
            # Almacenar el CAPTCHA para verificación posterior
            captcha_store[client_ip] = {
                'hash': captcha_hash,
                'timestamp': time.time(),
                'solved': False
            }
            
            self._set_headers()
            response = {
                'captcha_text': captcha_text,
                'captcha_id': captcha_hash[:10]
            }
            self.wfile.write(json.dumps(response).encode())
            logger.info(f"CAPTCHA generado para IP {client_ip}")
        except Exception as e:
            logger.error(f"Error al generar CAPTCHA: {str(e)}")
            self._handle_server_error(str(e))
    
    # Verificar si el usuario puede enviar un nuevo reporte
    def _get_report_status(self):
        """Verifica si el usuario puede enviar un nuevo reporte."""
        try:
            client_ip = get_client_ip(self)
            
            # Verificar si el usuario ha enviado un reporte recientemente
            can_report = True
            cooldown_remaining = 0
            
            if client_ip in captcha_store and captcha_store[client_ip].get('solved', False):
                solve_time = captcha_store[client_ip].get('solve_timestamp', 0)
                elapsed = time.time() - solve_time
                
                if elapsed < REPORT_COOLDOWN:
                    can_report = False
                    cooldown_remaining = int(REPORT_COOLDOWN - elapsed)
            
            self._set_headers()
            response = {
                'can_report': can_report,
                'cooldown_remaining': cooldown_remaining
            }
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            logger.error(f"Error al verificar estado de reporte: {str(e)}")
            self._handle_server_error(str(e))
    
    # Obtener reportes
    def _get_reports(self):
        try:
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Obtener reportes activos (no expirados)
            now = datetime.datetime.now().isoformat()
            c.execute('SELECT * FROM reports WHERE expires_at > ? ORDER BY created_at DESC LIMIT 500', (now,))
            reports = [dict(row) for row in c.fetchall()]
            
            conn.close()
            
            # Sanitizar datos antes de enviarlos
            for report in reports:
                if 'description' in report:
                    report['description'] = escape(report['description'])
            
            self._set_headers()
            self.wfile.write(json.dumps(reports).encode())
            logger.info(f"Devolviendo {len(reports)} reportes activos")
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al obtener reportes: {str(e)}")
            self._handle_server_error(str(e))
        except Exception as e:
            logger.error(f"Error al obtener reportes: {str(e)}")
            self._handle_server_error(str(e))
    
    # Obtener un reporte específico
    def _get_report(self, report_id):
        try:
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
            report = c.fetchone()
            
            conn.close()
            
            if not report:
                self._handle_client_error('Reporte no encontrado')
                return
                
            self._set_headers()
            self.wfile.write(json.dumps(dict(report)).encode())
            
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al obtener reporte: {str(e)}")
            self._handle_server_error(str(e))
        except Exception as e:
            logger.error(f"Error al obtener reporte: {str(e)}")
            self._handle_server_error(str(e))
    
    # Crear reporte
    def _create_report(self, post_data):
        try:
            data = json.loads(post_data.decode())
            client_ip = get_client_ip(self)
            
            # Verificar si hay un CAPTCHA pendiente
            if 'captcha_hash' not in data or 'captcha_answer' not in data:
                self._handle_client_error('Se requiere completar el CAPTCHA')
                return
                
            # Verificar que el CAPTCHA es válido
            captcha_hash = data['captcha_hash']
            captcha_answer = data['captcha_answer'].upper()  # Convertir a mayúsculas para comparación
            
            if client_ip not in captcha_store:
                self._handle_client_error('CAPTCHA expirado o inválido, solicita uno nuevo')
                return
                
            stored_captcha = captcha_store[client_ip]
            
            # Verificar que el hash coincide
            if stored_captcha['hash'][:10] != captcha_hash:
                self._handle_client_error('CAPTCHA inválido')
                return
                
            # Verificar que el CAPTCHA no ha expirado
            if time.time() - stored_captcha['timestamp'] > CAPTCHA_EXPIRY:
                self._handle_client_error('CAPTCHA expirado, solicita uno nuevo')
                return
                
            # Verificar que la respuesta es correcta
            answer_hash = hashlib.sha256(captcha_answer.encode()).hexdigest()
            if answer_hash != stored_captcha['hash']:
                self._handle_client_error('Respuesta de CAPTCHA incorrecta')
                return
                
            # Verificar cooldown
            if stored_captcha.get('solved', False):
                solve_time = stored_captcha.get('solve_timestamp', 0)
                elapsed = time.time() - solve_time
                
                if elapsed < REPORT_COOLDOWN:
                    cooldown_remaining = int(REPORT_COOLDOWN - elapsed)
                    self._handle_client_error(f'Debes esperar {cooldown_remaining} segundos para enviar otro reporte')
                    return
            
            # Validar datos
            required_fields = ['report_type', 'latitude', 'longitude', 'description']
            for field in required_fields:
                if field not in data:
                    self._handle_client_error(f'Falta el campo {field}')
                    return
            
            # Validar tipo de reporte
            if data['report_type'] not in REPORT_COLORS:
                self._handle_client_error('Tipo de reporte inválido')
                return
                
            # Validar coordenadas
            try:
                lat = float(data['latitude'])
                lng = float(data['longitude'])
                if lat < -90 or lat > 90 or lng < -180 or lng > 180:
                    self._handle_client_error('Coordenadas geográficas inválidas')
                    return
            except ValueError:
                self._handle_client_error('Coordenadas geográficas inválidas')
                return
            
            # Validar longitud de la descripción
            if len(data['description']) > 1000:
                self._handle_client_error('La descripción es demasiado larga (máximo 1000 caracteres)')
                return
                
            # Sanitizar descripción
            description = escape(data['description'])
            
            # Asignar color según el tipo de reporte
            color = REPORT_COLORS.get(data['report_type'], 'red')
            
            # Calcular fechas
            now = datetime.datetime.now()
            created_at = now.isoformat()
            expires_at = (now + datetime.timedelta(days=30)).isoformat()
            
            # Usar with para asegurar que la conexión se cierre correctamente
            with sqlite3.connect('reports.db') as conn:
                c = conn.cursor()
                c.execute('''
                INSERT INTO reports 
                (report_type, latitude, longitude, description, color, created_at, expires_at, likes, dislikes) 
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                ''', (
                    data['report_type'], 
                    data['latitude'], 
                    data['longitude'], 
                    description,
                    color,
                    created_at,
                    expires_at
                ))
                report_id = c.lastrowid
                conn.commit()
                
                # Obtener el reporte recién creado
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
                report = dict(c.fetchone())
            
            # Actualizar estado del CAPTCHA como resuelto
            captcha_store[client_ip]['solved'] = True
            captcha_store[client_ip]['solve_timestamp'] = time.time()
            
            self._set_headers(status=201)
            self.wfile.write(json.dumps(report).encode())
            logger.info(f"Reporte creado con ID {report_id} de tipo {data['report_type']}")
        except json.JSONDecodeError:
            self._handle_client_error('Formato JSON inválido')
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al crear reporte: {str(e)}")
            self._handle_server_error(str(e))
        except Exception as e:
            logger.error(f"Error al crear reporte: {str(e)}")
            self._handle_server_error(str(e))
    
    # Votar en un reporte
    def _vote_report(self, report_id, post_data):
        try:
            data = json.loads(post_data.decode())
            
            if 'vote_type' not in data:
                self.send_response(400)
                self.end_headers()
                response = {'error': 'Falta el tipo de voto'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            vote_type = data['vote_type']
            if vote_type not in ['like', 'dislike']:
                self.send_response(400)
                self.end_headers()
                response = {'error': 'Tipo de voto inválido'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Verificar que el reporte existe y no ha expirado
            now = datetime.datetime.now().isoformat()
            c.execute('SELECT * FROM reports WHERE id = ? AND expires_at > ?', (report_id, now))
            report = c.fetchone()
            
            if not report:
                conn.close()
                self.send_response(404)
                self.end_headers()
                response = {'error': 'Reporte no encontrado o expirado'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Actualizar votos
            if vote_type == 'like':
                c.execute('UPDATE reports SET likes = likes + 1 WHERE id = ?', (report_id,))
            else:
                c.execute('UPDATE reports SET dislikes = dislikes + 1 WHERE id = ?', (report_id,))
            
            conn.commit()
            
            # Obtener el reporte actualizado
            c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
            updated_report = dict(c.fetchone())
            
            conn.close()
            
            self._set_headers()
            self.wfile.write(json.dumps(updated_report).encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            response = {'error': str(e)}
            self.wfile.write(json.dumps(response).encode())
    
    # Verificar noticia con Perplexity API
    def _verify_news(self, post_data):
        try:
            data = json.loads(post_data.decode())
            
            if 'content' not in data and 'url' not in data:
                self._handle_client_error('Debes proporcionar contenido o URL para verificar')
                return
            
            # Preparar el contenido a verificar
            content_to_verify = data.get('content', '').strip()
            url_to_verify = data.get('url', '').strip()
            
            # Validar longitud del contenido
            if content_to_verify and len(content_to_verify) > 10000:
                self._handle_client_error('El contenido es demasiado largo (máximo 10000 caracteres)')
                return
                
            # Validar URL
            if url_to_verify and not url_to_verify.startswith(('http://', 'https://')):
                self._handle_client_error('URL inválida, debe comenzar con http:// o https://')
                return
            
            # Si hay una URL pero no hay contenido, intentamos obtener el contenido de la URL
            # Si hay una URL pero no hay contenido, intentamos obtener el contenido de la URL
            if url_to_verify and not content_to_verify:
                try:
                    url_response = requests.get(url_to_verify, timeout=10)
                    if url_response.status_code == 200:
                        # Esto es muy simple, en producción querrías usar BeautifulSoup para extraer el texto
                        content_from_url = f"URL: {url_to_verify}\n\nContenido extraído: {url_response.text[:5000]}"
                    else:
                        content_from_url = f"No se pudo acceder a la URL: {url_to_verify}"
                except Exception as url_error:
                    content_from_url = f"Error al acceder a la URL {url_to_verify}: {str(url_error)}"
                
                # Usamos el contenido extraído de la URL
                content_to_verify = content_from_url
            
            # Crear un hash único del contenido para el caché
            content_hash = str(hash(content_to_verify))
            
            # Comprobar si ya tenemos una verificación en caché
            if content_hash in verification_cache:
                cache_entry = verification_cache[content_hash]
                # Comprobar si la entrada de caché ha expirado
                if time.time() - cache_entry['timestamp'] < CACHE_EXPIRY:
                    logger.info(f"Usando respuesta de caché para verificación")
                    self._set_headers()
                    response = {
                        'verification': cache_entry['verification'],
                        'cached': True
                    }
                    self.wfile.write(json.dumps(response).encode())
                    return
            
            # Construir el prompt para Perplexity
            prompt = """
            Actúa como un verificador de noticias especializado en elecciones de Ecuador 2025. 
            
            Analiza cuidadosamente el siguiente contenido:
            
            """ + (content_to_verify if content_to_verify else url_to_verify) + """
            
            Por favor, verifica la veracidad de esta información considerando:
            1. Hechos verificables vs opiniones
            2. Fuentes oficiales electorales de Ecuador
            3. Contradicciones o inconsistencias
            4. Contexto completo de la información
            5. Posibles sesgos o manipulación
            
            Responde con el siguiente formato HTML, manteniendo exactamente las etiquetas y estructura:

            <div class="verification-report">
                <div class="verification-header">
                    <h2>Verificación de información electoral</h2>
                    <p class="verification-date">Fecha: [FECHA ACTUAL]</p>
                </div>
                
                <div class="verification-summary">
                    <h3>Resumen del análisis</h3>
                    <p>[UN RESUMEN CONCISO DEL CONTENIDO ANALIZADO Y SU CONTEXTO, 1-2 PÁRRAFOS]</p>
                </div>
                
                <div class="verification-result">
                    <h3>Resultado de la verificación</h3>
                    <div class="result-badge [RESULTADO]">[RESULTADO]</div>
                    <p>[BREVE EXPLICACIÓN DEL RESULTADO]</p>
                </div>
                
                <div class="verification-details">
                    <h3>Análisis detallado</h3>
                    <ul>
                        <li><strong>Evidencia:</strong> [ANÁLISIS DE EVIDENCIA DISPONIBLE]</li>
                        <li><strong>Contexto:</strong> [ANÁLISIS DEL CONTEXTO]</li>
                        <li><strong>Fuentes:</strong> [ANÁLISIS DE LAS FUENTES]</li>
                        <li><strong>Consistencia:</strong> [ANÁLISIS DE CONSISTENCIA DE LA INFORMACIÓN]</li>
                    </ul>
                </div>
                
                <div class="verification-sources">
                    <h3>Fuentes consultadas</h3>
                    <ul>
                        [LISTA DE FUENTES CONSULTADAS CON ENLACES DONDE SEA POSIBLE,esto debe estar relacionado o tener concordancia con la consulta realizada]
                    </ul>
                </div>
                
                <div class="verification-recommendations">
                    <h3>Recomendaciones</h3>
                    <ul>
                        [3-5 RECOMENDACIONES PARA EL LECTOR]
                    </ul>
                </div>
            </div>

            Para el campo [RESULTADO], usa exclusivamente una de estas opciones:
            - "Verificado" (si la información es confirmada por fuentes confiables)
            - "Impreciso" (si la información contiene algunos datos correctos pero otros incorrectos o engañosos)
            - "No Verificado" (si no hay suficiente evidencia para confirmar o negar)
            - "Falso" (si la información es claramente incorrecta)

            No mezcles opciones ni muestres más de un resultado.

            La clase CSS debe coincidir con el resultado en minúsculas y sin espacios.
            """
            
            # Llamar a la API de Perplexity
            headers = {
                "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "sonar",  # Usar el modelo sonar como solicitado
                "messages": [
                    {"role": "system", "content": "Eres un verificador de noticias especializado en elecciones de Ecuador 2025."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1024,  # Limitar la longitud de la respuesta
                "temperature": 0.7  # Ajustar la creatividad
            }
            
            logger.info(f"Enviando solicitud a Perplexity API...")
            
            # Intentar hasta 3 veces en caso de fallos
            max_attempts = 3
            attempts = 0
            success = False
            
            while attempts < max_attempts and not success:
                attempts += 1
                try:
                    perplexity_response = requests.post(
                        "https://api.perplexity.ai/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=60  # Aumentar el timeout para dar tiempo a la API
                    )
                    
                    logger.info(f"Respuesta de Perplexity - Status: {perplexity_response.status_code}")
                    
                    if perplexity_response.status_code == 200:
                        success = True
                    elif perplexity_response.status_code == 429:  # Rate limit
                        logger.warning("Límite de tasa de API excedido, esperando antes de reintentar...")
                        time.sleep(5)  # Esperar 5 segundos antes de reintentar
                    else:
                        logger.error(f"Error en API Perplexity: {perplexity_response.text}")
                        # Si no es un error de límite de tasa, no reintentamos
                        break
                except Exception as e:
                    logger.error(f"Error en la solicitud a Perplexity: {str(e)}")
                    time.sleep(2)  # Esperar 2 segundos antes de reintentar
            
            if not success:
                self._handle_server_error(f"No se pudo conectar con el servicio de verificación después de {max_attempts} intentos")
                return
            
            try:
                result = perplexity_response.json()
                verification_text = result['choices'][0]['message']['content']
            except (KeyError, IndexError) as e:
                logger.error(f"Error al extraer contenido de respuesta: {str(e)}")
                logger.error(f"Respuesta completa: {json.dumps(result)}")
                verification_text = "No se pudo obtener una verificación. Por favor, intenta de nuevo más tarde."
            
            logger.info("Verificación completada exitosamente")
            
            # Guardar en caché
            if len(verification_cache) >= MAX_CACHE_SIZE:
                # Eliminar la entrada más antigua
                oldest_key = min(verification_cache.keys(), key=lambda k: verification_cache[k]['timestamp'])
                del verification_cache[oldest_key]
            
            verification_cache[content_hash] = {
                'verification': verification_text,
                'timestamp': time.time()
            }
            
            self._set_headers()
            response = {
                'verification': verification_text
            }
            self.wfile.write(json.dumps(response).encode())
            
        except json.JSONDecodeError:
            self._handle_client_error('Formato JSON inválido')
        except Exception as e:
            logger.error(f"Error en la verificación: {str(e)}")
            self._handle_server_error(str(e))
    
    # Registro de periodista
    def _register_journalist(self, post_data):
        try:
            data = json.loads(post_data.decode())
            
            # Validar datos
            required_fields = ['full_name', 'email', 'password', 'organization', 'role']
            for field in required_fields:
                if field not in data:
                    self._handle_client_error(f'Falta el campo {field}')
                    return
            
            # Validar correo electrónico
            email = data['email'].strip().lower()
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self._handle_client_error('Correo electrónico inválido')
                return
                
            # Verificar si el correo ya está registrado
            conn = sqlite3.connect('reports.db')
            c = conn.cursor()
            c.execute('SELECT email FROM journalists WHERE email = ?', (email,))
            existing_email = c.fetchone()
            
            if existing_email:
                conn.close()
                self._handle_client_error('Este correo electrónico ya está registrado')
                return
                
            # Generar hash de contraseña
            password_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
            
            # Insertar nuevo periodista
            now = datetime.datetime.now().isoformat()
            c.execute('''
            INSERT INTO journalists 
            (full_name, email, password_hash, organization, role, credentials, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['full_name'],
                email,
                password_hash.decode(),
                data['organization'],
                data['role'],
                data.get('credentials', ''),
                now
            ))
            
            journalist_id = c.lastrowid
            conn.commit()
            
            # Obtener el periodista recién creado
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT id, full_name, email, organization, role, created_at FROM journalists WHERE id = ?', (journalist_id,))
            journalist = dict(c.fetchone())
            
            conn.close()
            
            self._set_headers(status=201)
            self.wfile.write(json.dumps(journalist).encode())
            logger.info(f"Periodista registrado con ID {journalist_id}")
            
        except json.JSONDecodeError:
            self._handle_client_error('Formato JSON inválido')
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al registrar periodista: {str(e)}")
            self._handle_server_error(str(e))
        except Exception as e:
            logger.error(f"Error al registrar periodista: {str(e)}")
            self._handle_server_error(str(e))
    
    # Inicio de sesión de periodista
    def _login_journalist(self, post_data):
        try:
            data = json.loads(post_data.decode())
            
            # Validar datos
            if 'email' not in data or 'password' not in data:
                self._handle_client_error('Faltan credenciales')
                return
                
            email = data['email'].strip().lower()
            password = data['password']
            
            # Buscar periodista por email
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM journalists WHERE email = ?', (email,))
            journalist = c.fetchone()
            
            if not journalist:
                conn.close()
                self._handle_client_error('Credenciales inválidas')
                return
                
            # Verificar contraseña
            if not bcrypt.checkpw(password.encode(), journalist['password_hash'].encode()):
                conn.close()
                self._handle_client_error('Credenciales inválidas')
                return
                
            # Actualizar último inicio de sesión
            now = datetime.datetime.now().isoformat()
            c.execute('UPDATE journalists SET last_login = ? WHERE id = ?', (now, journalist['id']))
            conn.commit()
            
            # Generar token JWT
            payload = {
                'sub': str(journalist['id']),  # Convertir a string
                'iat': datetime.datetime.utcnow(),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
            
            # Preparar respuesta
            user_data = {
                'id': journalist['id'],
                'full_name': journalist['full_name'],
                'email': journalist['email'],
                'organization': journalist['organization'],
                'role': journalist['role']
            }
            
            response = {
                'token': token,
                'user': user_data
            }
            
            conn.close()
            
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            logger.info(f"Inicio de sesión exitoso para periodista {journalist['id']}")
            
        except json.JSONDecodeError:
            self._handle_client_error('Formato JSON inválido')
        except Exception as e:
            logger.error(f"Error en inicio de sesión: {str(e)}")
            self._handle_server_error(str(e))
    
    # Crear verificación de reporte
    def _create_verification(self, post_data):
        try:
            data = json.loads(post_data.decode())
            
            # Validar token JWT
            token = None
            if 'Authorization' in self.headers:
                auth_header = self.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    print("Token recibido:", token[:20] + "..." if token else "None")  # Para depuración
            
            if not token:
                self.send_response(401)
                self.end_headers()
                response = {'error': 'Token no proporcionado'}
                self.wfile.write(json.dumps(response).encode())
                return
                    
            try:
                # Decodificar token
                print("Intentando decodificar token con JWT_SECRET:", JWT_SECRET[:5] + "***")  # Para depuración
                payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                journalist_id = payload['sub']
                print(f"Token decodificado. journalist_id: {journalist_id}, tipo: {type(journalist_id)}")
                
                # Verificar que el periodista existe
                conn = sqlite3.connect('reports.db')
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute('SELECT * FROM journalists WHERE id = ?', (journalist_id,))
                journalist = c.fetchone()
                
                if not journalist:
                    conn.close()
                    self._handle_client_error('Periodista no encontrado')
                    return
                    
                print(f"Periodista encontrado: ID {journalist['id']}, Nombre: {journalist['full_name']}")
                
            except jwt.ExpiredSignatureError as e:
                logger.error(f"Token expirado: {str(e)}")
                self.send_response(401)
                self.end_headers()
                response = {'error': 'Token expirado'}
                self.wfile.write(json.dumps(response).encode())
                return
            except jwt.InvalidTokenError as e:
                logger.error(f"Token inválido: {str(e)}")
                self.send_response(401)
                self.end_headers()
                response = {'error': f'Error al verificar token: {str(e)}'}
                self.wfile.write(json.dumps(response).encode())
                return
            except Exception as e:
                logger.error(f"Error al procesar token: {str(e)}")
                self.send_response(401)
                self.end_headers()
                response = {'error': f'Error al verificar token: {str(e)}'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Validar datos
            required_fields = ['report_id', 'verification_status', 'organization', 'explanation', 'sources']
            for field in required_fields:
                if field not in data:
                    self._handle_client_error(f'Falta el campo {field}')
                    return
            
            try:
                # Verificar que el reporte existe
                c.execute('SELECT * FROM reports WHERE id = ?', (data['report_id'],))
                report = c.fetchone()
                
                if not report:
                    conn.close()
                    self._handle_client_error('Reporte no encontrado')
                    return
                    
                # Verificar si ya existe una verificación para este reporte
                c.execute('SELECT * FROM verifications WHERE report_id = ?', (data['report_id'],))
                existing_verification = c.fetchone()
                
                if existing_verification:
                    conn.close()
                    self._handle_client_error('Este reporte ya ha sido verificado')
                    return
                    
                # Crear verificación
                now = datetime.datetime.now().isoformat()
                print(f"Insertando verificación para reporte {data['report_id']} por periodista {journalist_id}")
                
                c.execute('''
                INSERT INTO verifications 
                (report_id, journalist_id, verification_status, evidence_url, organization, explanation, sources, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['report_id'],
                    journalist_id,
                    data['verification_status'],
                    data.get('evidence_url', ''),
                    data['organization'],
                    data['explanation'],
                    data['sources'],
                    now
                ))
                
                verification_id = c.lastrowid
                print(f"Verificación creada con ID {verification_id}")
                
                # Actualizar reporte con estado de verificación
                c.execute('''
                UPDATE reports 
                SET verified = 1, verified_status = ?, verification_id = ? 
                WHERE id = ?
                ''', (
                    data['verification_status'],
                    verification_id,
                    data['report_id']
                ))
                
                conn.commit()
                print(f"Reporte {data['report_id']} actualizado con estado de verificación")
                
                # Obtener la verificación recién creada
                c.execute('''
                SELECT v.*, j.full_name as journalist_name 
                FROM verifications v
                JOIN journalists j ON v.journalist_id = j.id
                WHERE v.id = ?
                ''', (verification_id,))
                verification = dict(c.fetchone())
                
                conn.close()
                
                self._set_headers(status=201)
                self.wfile.write(json.dumps(verification).encode())
                logger.info(f"Verificación creada con ID {verification_id} para reporte {data['report_id']}")
                
            except sqlite3.Error as e:
                logger.error(f"Error de base de datos al crear verificación: {str(e)}")
                self._handle_server_error(f"Error de base de datos: {str(e)}")
                return
            except Exception as e:
                logger.error(f"Error al crear verificación: {str(e)}")
                self._handle_server_error(str(e))
                return
                
        except json.JSONDecodeError:
            self._handle_client_error('Formato JSON inválido')
        except Exception as e:
            logger.error(f"Error general al crear verificación: {str(e)}")
            self._handle_server_error(str(e))
    
    # Obtener detalles de verificación
    def _get_verification_details(self, report_id):
        try:
            conn = sqlite3.connect('reports.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Verificar que el reporte existe
            c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
            report = c.fetchone()
            
            if not report:
                conn.close()
                self._handle_client_error('Reporte no encontrado')
                return
                
            # Verificar si existe una verificación para este reporte
            c.execute('''
            SELECT v.*, j.full_name as journalist_name 
            FROM verifications v
            JOIN journalists j ON v.journalist_id = j.id
            WHERE v.report_id = ?
            ''', (report_id,))
            verification = c.fetchone()
            
            if not verification:
                conn.close()
                self._handle_client_error('Este reporte no ha sido verificado')
                return
                
            # Preparar respuesta
            response = {
                'report': dict(report),
                'verification': dict(verification)
            }
            
            conn.close()
            
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos al obtener verificación: {str(e)}")
            self._handle_server_error(str(e))
        except Exception as e:
            logger.error(f"Error al obtener verificación: {str(e)}")
            self._handle_server_error(str(e))
    
    # Servir archivo estático
    def _serve_file(self, file_path, content_type):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            self._set_headers(content_type)
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            response = {'error': 'Archivo no encontrado'}
            self.wfile.write(json.dumps(response).encode())

# Inicializar base de datos
try:
    init_db()
except Exception as e:
    logger.error(f"Error al inicializar la base de datos: {str(e)}")
    sys.exit(1)

# Probar la API de Perplexity
api_working = test_perplexity_api()
if not api_working:
    logger.warning("La API de Perplexity no está funcionando correctamente.")
    logger.warning("El verificador de noticias podría no funcionar. Revisa la clave API.")
else:
    logger.info("Verificador de noticias listo para usar.")

# Configurar y ejecutar servidor
import os

# Modifica la función run para usar el puerto que proporciona Railway
def run(server_class=HTTPServer, handler_class=RequestHandler, port=None):
    port = int(os.environ.get('PORT', 5000))
    try:
        server_address = ('0.0.0.0', port)  # Cambia a 0.0.0.0 para aceptar conexiones externas
        httpd = server_class(server_address, handler_class)
        logger.info(f'Servidor iniciado en puerto: {port}')
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario")
    except Exception as e:
        logger.error(f"Error al iniciar el servidor: {str(e)}")
    finally:
        try:
            httpd.server_close()
            logger.info("Servidor cerrado correctamente")
        except:
            pass

if __name__ == '__main__':
    run()