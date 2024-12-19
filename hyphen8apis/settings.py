import os
import sentry_sdk
from pathlib import Path
from sentry_sdk.integrations.django import DjangoIntegration
from decouple import config
from pathlib import Path
sentry_sdk.init(
    dsn=config('SENTRY_SDK_KEY', default='your-default-secret-key'),
    integrations=[DjangoIntegration()],
    traces_sample_rate=1.0,
    send_default_pii=config('SEND_DEFAULT_PII', default=False),
)
SECURE_HSTS_SECONDS = config('SECURE_HSTS_SECONDS', default=31536000)   
SECURE_HSTS_INCLUDE_SUBDOMAINS = config('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=False, cast=bool) 
SECURE_HSTS_PRELOAD = config('SECURE_HSTS_PRELOAD', default=False, cast=bool) 
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=False, cast=bool) 
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config('SECRET_KEY', default='your-default-secret-key')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = ['127.0.0.1','textextract.hyphen8.com','localhost']
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'users',
    'rest_framework',
    'rest_framework.authtoken',
    'subscriptions',
    'apiv1',
    'tinymce',
    'documentation',
]
SITE_ID = 1
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=False, cast=bool)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
ROOT_URLCONF = 'hyphen8apis.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],  # Ensure this points to your templates directory
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
WSGI_APPLICATION = 'hyphen8apis.wsgi.application'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static"),
)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
STATIC_ROOT = '/home/ubuntu/djangoAPITesting/staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'users.CustomUser'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='your-default-secret-key')
EMAIL_PORT = config('EMAIL_PORT', default='your-default-secret-key')
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=False, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='your-default-secret-key')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='your-default-secret-key')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='your-default-secret-key')
SECURE_CROSS_ORIGIN_OPENER_POLICY = None
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apiv1.authentication.CustomTokenAuthentication',  
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': config('DJANGO_ERROR_LOG_FILE', default='/home/ubuntu/djangoAPITesting/logs/django_errors.log'),
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR',
            'propagate': True,
        },
    },
}
SALESFORCE_CLIENT_ID = config('SALESFORCE_CLIENT_ID', default='your-default-secret-key')
SALESFORCE_CLIENT_SECRET = config('SALESFORCE_SECRET', default='your-default-secret-key')
SALESFORCE_CALLBACK_URL = config('SALESFORCE_CALLBACK_URL', default='https://127.0.0.1:8000/salesforce/callback/')