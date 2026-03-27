"""
WSGI config for CloudDataEncryption project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CloudDataEncryption.settings')

application = get_wsgi_application()

