#!/usr/bin/env python3
import asyncio
import logging
import signal
import sys
import threading
import time
import os
import socket
import json
from pathlib import Path
from waitress import serve
from flask import Flask, jsonify, send_file

# =========================
# Configuración de LOGGING
# =========================
LOG_PATH = os.path.join(os.getcwd(), "data", "logs", "proxy.log")

# Crear directorios necesarios primero
BASE_DIR = Path(__file__).parent
(BASE_DIR / "data" / "logs").mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# =========================
# Cargar configuración OPTIMIZADA para Render
# =========================
def load_config():
    """Cargar configuración optimizada para Render"""
    BASE_DIR = Path(__file__).parent
    
    # Configuración específica para Render
    RENDER_CONFIG = {
        "proxy_host": "0.0.0.0",
        "proxy_port": 8080,  # Puerto principal para Render
        "web_host": "0.0.0.0",
        "web_port": 8081,    # Puerto secundario
        "dashboard_domain": "proxy-familiar.onrender.com",
        "dashboard_title": "Proxy Familiar - Render",
        "security": {
            "require_auth": False,  # Desactivar auth para debugging
            "session_timeout": 3600,
            "max_login_attempts": 3,
            "lockout_time": 900
        },
        "database_url": f"sqlite:///{BASE_DIR}/data/proxy.db",
        "cache_enabled": True,
        "cache_size": 100,
        "cache_ttl": 3600,
        "blocking_enabled": True,
        "youtube_blocking": False,  # Desactivar temporalmente
        "aggressive_filtering": False,  # Desactivar temporalmente
        "block_trackers": True,
        "log_level": "INFO",
        "cert_dir": str(BASE_DIR / "config" / "certs"),
        "block_lists": {
            "easylist": "https://easylist.to/easylist/easylist.txt",
            "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt"
        },
        "whitelist": [
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "microsoft.com",
            "youtube.com",
            "www.youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "gvt1.com",
            "google.com",
            "render.com",
            "onrender.com"
        ],
        "blacklist": [
            "googleads.g.doubleclick.net",
            "connect.facebook.net",
            "ads.tiktok.com",
            "googlesyndication.com",
            "doubleclick.net",
            "googleadservices.com"
        ],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    }
    
    config_path = BASE_DIR / "config" / "config.json"
    
    # Crear carpetas necesarias
    (BASE_DIR / "config").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "logs").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "block_lists").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "cache").mkdir(parents=True, exist_ok=True)

    try:
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            
            # Combinar configuraciones
            config = RENDER_CONFIG.copy()
            
            def deep_update(default, user):
                for key, value in user.items():
                    if isinstance(value, dict) and key in default and isinstance(default[key], dict):
                        deep_update(default[key], value)
                    else:
                        default[key] = value
            
            deep_update(config, user_config)
            
        else:
            config = RENDER_CONFIG.copy()
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info(f"Configuración Render creada en {config_path}")

    except Exception as e:
        logger.warning(f"Error al cargar configuración: {e}. Usando valores por defecto.")
        config = RENDER_CONFIG.copy()

    return config

# =========================
# Importar otros módulos con manejo mejorado
# =========================
def import_modules():
    """Importar módulos con mejor manejo de errores"""
    modules_loaded = {}
    
    try:
        from core.proxy_server import AdvancedProxyServer
        modules_loaded['proxy_server'] = True
        logger.info("✅ Módulo proxy_server cargado")
    except ImportError as e:
        logger.error(f"❌ Error cargando proxy_server: {e}")
        modules_loaded['proxy_server'] = False
        
    try:
        from web.app import create_web_app
        modules_loaded['web_app'] = True
        logger.info("✅ Módulo web_app cargado")
    except ImportError as e:
        logger.error(f"❌ Error cargando web_app: {e}")
        modules_loaded['web_app'] = False
        
    try:
        from data.database import init_database
        modules_loaded['database'] = True
        logger.info("✅ Módulo database cargado")
    except ImportError as e:
        logger.error(f"❌ Error cargando database: {e}")
        modules_loaded['database'] = False
        
    return modules_loaded

# =========================
# Servidor Flask SIMPLIFICADO para Render
# =========================
def create_simple_app():
    """Crear aplicación Flask simplificada"""
    app = Flask(__name__)
    
    @app.route("/")
    def index():
        return """
        <html>
            <head>
                <title>Proxy Familiar - Render</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .status { padding: 10px; border-radius: 5px; margin: 10px 0; }
                    .running { background: #d4edda; color: #155724; }
                    .info { background: #d1ecf1; color: #0c5460; }
                </style>
            </head>
            <body>
                <h1>🚀 Proxy Familiar</h1>
                <div class="status running">
                    <strong>✅ Servicio Activo</strong>
                    <p>Proxy ejecutándose en Render</p>
                </div>
                <div class="status info">
                    <p><strong>URL Principal:</strong> https://proxy-familiar.onrender.com</p>
                    <p><strong>Puerto Proxy:</strong> 8080</p>
                    <p><strong>Dashboard:</strong> 8081</p>
                </div>
                <div>
                    <h3>Enlaces útiles:</h3>
                    <ul>
                        <li><a href="/logs">Ver Logs</a></li>
                        <li><a href="/status">Estado del Servicio</a></li>
                        <li><a href="/config">Configuración</a></li>
                    </ul>
                </div>
            </body>
        </html>
        """
    
    @app.route("/logs")
    def ver_logs():
        """Ver logs en el navegador"""
        if not os.path.exists(LOG_PATH):
            return jsonify({"error": "El archivo de logs no existe"}), 404
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                contenido = f.read()
            return f"<pre>{contenido}</pre>"
        except Exception as e:
            return f"<p>Error leyendo logs: {e}</p>"
    
    @app.route("/logs/download")
    def descargar_logs():
        """Descargar el archivo de logs"""
        if not os.path.exists(LOG_PATH):
            return jsonify({"error": "El archivo de logs no existe"}), 404
        return send_file(LOG_PATH, as_attachment=True)
    
    @app.route("/status")
    def status():
        """Endpoint de estado"""
        return jsonify({
            "status": "running",
            "service": "Domestic Proxy",
            "timestamp": time.time(),
            "environment": "render"
        })
    
    @app.route("/config")
    def show_config():
        """Mostrar configuración actual"""
        config = load_config()
        safe_config = config.copy()
        # Ocultar información sensible
        if 'database_url' in safe_config:
            safe_config['database_url'] = '***'
        return jsonify(safe_config)
    
    return app

# =========================
# Clase principal del proxy MEJORADA
# =========================
class DomesticProxy:
    def __init__(self):
        self.config = load_config()
        self.proxy_server = None
        self.web_app = None
        self.modules_loaded = import_modules()
        self.is_running = False

    async def start_proxy_server(self):
        """Iniciar servidor proxy con mejor manejo de errores"""
        try:
            if not self.modules_loaded.get('proxy_server', False):
                logger.error("❌ Módulo proxy_server no disponible")
                return
                
            logger.info("🔄 Iniciando servidor proxy...")
            
            # Inicializar base de datos si está disponible
            if self.modules_loaded.get('database', False):
                try:
                    from data.database import init_database
                    await init_database()
                    logger.info("✅ Base de datos inicializada")
                except Exception as e:
                    logger.warning(f"⚠️ Error inicializando BD: {e}")
            
            self.proxy_server = AdvancedProxyServer(self.config)
            await self.proxy_server.start()
            
            self.is_running = True
            logger.info("✅ Servidor proxy iniciado correctamente")
            
        except Exception as e:
            logger.error(f"❌ Error crítico iniciando proxy: {e}")
            self.is_running = False
            raise

    def create_web_app(self):
        """Crear aplicación web - versión simplificada"""
        try:
            if self.modules_loaded.get('web_app', False):
                from web.app import create_web_app
                app = create_web_app(self.proxy_server, self.config)
                if app is not None:
                    logger.info("✅ Dashboard avanzado creado")
                    return app
            
            # Fallback a app simplificada
            logger.info("🔄 Usando dashboard simplificado")
            return create_simple_app()
            
        except Exception as e:
            logger.error(f"❌ Error creando app web: {e}")
            return create_simple_app()

    def start_web_dashboard(self):
        """Iniciar dashboard web optimizado para Render"""
        try:
            self.web_app = self.create_web_app()
            
            host = self.config['web_host']
            port = self.config['web_port']
            
            logger.info(f"🌐 Iniciando dashboard web en {host}:{port}...")
            
            # Usar waitress para producción
            serve(self.web_app, host=host, port=port, threads=4)
            
        except Exception as e:
            logger.error(f"❌ Error iniciando dashboard: {e}")
            # Último fallback
            emergency_app = create_simple_app()
            serve(emergency_app, host='0.0.0.0', port=8081)

    async def stop(self):
        """Detener servicios"""
        self.is_running = False
        if self.proxy_server:
            await self.proxy_server.stop()
        logger.info("🛑 Servicios detenidos")

def run_proxy_server(proxy_instance):
    """Ejecutar proxy server en loop asyncio"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(proxy_instance.start_proxy_server())
        # Mantener el loop corriendo
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Error en proxy server: {e}")
    finally:
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()

# =========================
# Manejo de señales para Render
# =========================
def signal_handler(signum, frame):
    """Manejar señales de terminación"""
    logger.info(f"Señal {signum} recibida, cerrando aplicación...")
    sys.exit(0)

# =========================
# Lanzamiento principal OPTIMIZADO
# =========================
if __name__ == "__main__":
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("🚀 Iniciando Domestic Proxy en Render...")
    
    # Crear instancia del proxy
    proxy = DomesticProxy()
    
    # Iniciar proxy en hilo separado
    logger.info("🔄 Iniciando servidor proxy en hilo separado...")
    proxy_thread = threading.Thread(
        target=run_proxy_server, 
        args=(proxy,), 
        daemon=True,
        name="ProxyServerThread"
    )
    proxy_thread.start()
    
    # Esperar inicialización
    logger.info("⏳ Esperando inicialización del proxy...")
    time.sleep(3)
    
    # Iniciar dashboard web en hilo principal
    logger.info("🌐 Iniciando dashboard web...")
    try:
        proxy.start_web_dashboard()
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)
