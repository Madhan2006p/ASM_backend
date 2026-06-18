from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-insecure-key')

DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '*').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_celery_results',
    'django_celery_beat',
    'rest_framework_simplejwt.token_blacklist',
    # Local apps
    'authentication',
    'accounts',
    'targets',
    'scans',
    'fuzzing',
    'vulnerabilities',
    'apk_scanner',
    'reconnaissance',
    'attacksurface',
    'assetDiscovery',
    'surface_monitoring',
    'brand_monitoring',
    'mobile_vapt',
    'findings',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'authentication.middleware.OrgAccessMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# ─── Database ─────────────────────────────────────────────────────────────────
import psycopg2

db_engine = os.getenv('DB_ENGINE', 'django.db.backends.postgresql')
db_name = os.getenv('DB_NAME', 'asm_db')
db_user = os.getenv('DB_USER', 'postgres')
db_password = os.getenv('DB_PASSWORD', 'postgres')
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', '5432')

use_sqlite = False
if db_engine == 'django.db.backends.postgresql':
    try:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port,
            connect_timeout=3
        )
        conn.close()
    except Exception as e:
        print(f"\n[!] PostgreSQL connection failed: {e}")
        print("[!] Falling back to SQLite3 database for robust operation.\n")
        use_sqlite = True

if use_sqlite or db_engine == 'django.db.backends.sqlite3':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': db_engine,
            'NAME': db_name,
            'USER': db_user,
            'PASSWORD': db_password,
            'HOST': db_host,
            'PORT': db_port,
        }
    }

# ─── REST Framework ───────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

# ─── JWT ──────────────────────────────────────────────────────────────────────
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}

# ─── CORS ─────────────────────────────────────────────────────────────────────
CORS_ALLOW_ALL_ORIGINS = True

from corsheaders.defaults import default_headers
CORS_ALLOW_HEADERS = list(default_headers) + [
    'ngrok-skip-browser-warning',
]

# ─── Cache ────────────────────────────────────────────────────────────────────
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://localhost:6379/1'),
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
        },
    },
    'tools': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://localhost:6379/2'),
        'TIMEOUT': 86400,
    },
}

# ─── Celery ───────────────────────────────────────────────────────────────────
CELERY_BROKER_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = 'django-db'
CELERY_TASK_ALWAYS_EAGER = True
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Asia/Kolkata'
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
CELERY_BEAT_SCHEDULE = {
    'run-scheduled-domain-scans-every-minute': {
        'task': 'attacksurface.tasks.run_scheduled_domain_scans',
        'schedule': 60.0,
    },
    'run-brand-monitor-checks-every-6-hours': {
        'task': 'brand_monitoring.tasks.run_brand_monitor_checks',
        'schedule': 21600.0,
    },
}

# ─── Scan tool paths (configure to actual paths) ──────────────────────────────
import sys
import shutil

def resolve_absolute_tool_path(tool_name, env_var=None):
    # 1. Check environment variable
    if env_var:
        env_val = os.getenv(env_var)
        if env_val and os.path.exists(env_val):
            return env_val

    # 2. Check system PATH using shutil.which
    resolved = shutil.which(tool_name)
    if resolved:
        return resolved

    # 3. Check Windows specific pip scripts fallback path
    if os.name == 'nt':
        # Try sysconfig-based user scripts directory (most general)
        try:
            import sysconfig
            user_scripts = sysconfig.get_paths('nt_user').get('scripts')
            if user_scripts:
                scripts_dir = Path(user_scripts)
                exe_path = scripts_dir / f"{tool_name}.exe"
                if exe_path.exists():
                    return str(exe_path)
                script_path = scripts_dir / tool_name
                if script_path.exists():
                    if tool_name == 'inql':
                        return [sys.executable, '-m', 'inql']
                    return str(script_path)
        except Exception:
            pass
        # Legacy fallback (samyu's store-installed Python)
        scripts_dir = Path(r"C:\Users\samyu\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts")
        exe_path = scripts_dir / f"{tool_name}.exe"
        if exe_path.exists():
            return str(exe_path)
        script_path = scripts_dir / tool_name
        if script_path.exists():
            if tool_name == 'inql':
                return [sys.executable, '-m', 'inql']
            return str(script_path)

    # Tool not found anywhere — return None (callers must handle)
    return None

DIRSEARCH_PATH = resolve_absolute_tool_path('dirsearch')
ARJUN_PATH = resolve_absolute_tool_path('arjun')
NUCLEI_PATH = resolve_absolute_tool_path('nuclei')
NMAP_PATH = resolve_absolute_tool_path('nmap')
TESTSSL_PATH = resolve_absolute_tool_path('testssl.sh')
HTTPX_PATH = resolve_absolute_tool_path('httpx')
INQL_PATH = resolve_absolute_tool_path('inql')
GAU_PATH = resolve_absolute_tool_path('gau')
WAYBACKURLS_PATH = resolve_absolute_tool_path('waybackurls')
GRPCURL_PATH = resolve_absolute_tool_path('grpcurl')
WAPITI_PATH = resolve_absolute_tool_path('wapiti')
# Prefer explicit env var, fall back to PATH, then to user-local install
GITLEAKS_PATH = resolve_absolute_tool_path('gitleaks', 'GITLEAKS_PATH')
# Reconnaissance / subdomain discovery tools
SUBFINDER_PATH = resolve_absolute_tool_path('subfinder', 'SUBFINDER_PATH')
ASSETFINDER_PATH = resolve_absolute_tool_path('assetfinder', 'ASSETFINDER_PATH')
FINDOMAIN_PATH = resolve_absolute_tool_path('findomain', 'FINDOMAIN_PATH')
NAABU_PATH = resolve_absolute_tool_path('naabu', 'NAABU_PATH')

# Nuclei templates path
_nuclei_tpl = os.getenv('NUCLEI_TEMPLATES_PATH')
if _nuclei_tpl and os.path.isdir(_nuclei_tpl):
    NUCLEI_TEMPLATES_PATH = _nuclei_tpl
else:
    _home_tpl = Path.home() / 'nuclei-templates'
    NUCLEI_TEMPLATES_PATH = str(_home_tpl) if _home_tpl.is_dir() else None
SCAN_OUTPUT_DIR = BASE_DIR / 'scan_outputs'
SCAN_OUTPUT_DIR.mkdir(exist_ok=True)
ALERT_EMAIL_USER = os.getenv('ALERT_EMAIL_USER', '')
ALERT_EMAIL_PASSWORD = os.getenv('ALERT_EMAIL_PASSWORD', '')
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM', 'asmm@localhost')
ALERT_EMAIL_TO = os.getenv('ALERT_EMAIL_TO', 'admin@localhost').split(',')
ALERT_SEVERITY_THRESHOLD = 'HIGH'
FARADAY_PIPELINE_URL = os.getenv('FARADAY_PIPELINE_URL', 'http://127.0.0.1:8001')
FARADAY_AUTO_IMPORT_NUCLEI = os.getenv('FARADAY_AUTO_IMPORT_NUCLEI', 'True').lower() in ('true', '1', 'yes')

# Direct Faraday connection settings (used for vulnerability import)
FARADAY_URL = os.getenv('FARADAY_URL', 'http://localhost:5985')
FARADAY_USERNAME = os.getenv('FARADAY_USERNAME', 'faraday')
FARADAY_PASSWORD = os.getenv('FARADAY_PASSWORD', 'M[9e@KwIHlu]E')
FARADAY_WORKSPACE = os.getenv('FARADAY_WORKSPACE', 'nuclei-asm')
FARADAY_VERIFY_SSL = os.getenv('FARADAY_VERIFY_SSL', 'false').lower() in ('true', '1', 'yes')

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ── MobSF settings ───────────────────────────────────────────────────────────
MOBSF_URL = os.getenv('MOBSF_URL', 'http://localhost:8002')
MOBSF_API_KEY = os.getenv('MOBSF_API_KEY', '2fbcd360100da6fb02a176e8d004e4932833fff5c9bae8dc4880dd3bce67222f')

# ── MobSF Docker auto-start settings ─────────────────────────────────────────
# Docker image to pull/use when no container exists yet
MOBSF_IMAGE = os.getenv('MOBSF_IMAGE', 'opensecurity/mobile-security-framework-mobsf:latest')
# Name given to the auto-managed container
MOBSF_CONTAINER_NAME = os.getenv('MOBSF_CONTAINER_NAME', 'mobsf_auto')
# Host port that MobSF listens on (must match MOBSF_URL port above)
MOBSF_HOST_PORT = int(os.getenv('MOBSF_HOST_PORT', 8002))
