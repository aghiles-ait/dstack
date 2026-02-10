from flask import Flask, request, Response, stream_with_context
import requests
import os
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Désactiver les warnings SSL de requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configuration: app nginx cible
TARGET_APP_ID = os.getenv('TARGET_APP_ID', 'bef6e480d2a425e8091689ce7c19fb5eddbfee5c')
TARGET_PORT = os.getenv('TARGET_PORT', '8080')
GATEWAY_DOMAIN = os.getenv('GATEWAY_DOMAIN', 'apps.ovh-tdx-dev.iex.ec')
GATEWAY_PORT = os.getenv('GATEWAY_PORT', '9204')

# URL de base de l'app nginx via le gateway
TARGET_BASE_URL = f"https://{TARGET_APP_ID}-{TARGET_PORT}.{GATEWAY_DOMAIN}:{GATEWAY_PORT}"

logger.info(f"Proxy configured: target={TARGET_BASE_URL}")

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
    """Proxy toutes les requêtes vers l'app nginx via le gateway"""
    # Construire l'URL cible
    if path:
        target_url = f"{TARGET_BASE_URL}/{path}"
    else:
        target_url = TARGET_BASE_URL
    
    # Ajouter les query parameters
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"
    
    logger.info(f"Proxying {request.method} {request.path} -> {target_url}")
    
    # Préparer les headers (exclure Host et Connection)
    headers = {}
    for key, value in request.headers:
        if key.lower() not in ['host', 'connection', 'content-length']:
            headers[key] = value
    
    # Préparer les données du body
    data = None
    if request.method in ['POST', 'PUT', 'PATCH']:
        data = request.get_data()
        if request.content_type:
            headers['Content-Type'] = request.content_type
    
    try:
        # Faire la requête vers l'app nginx via le gateway
        # verify=False pour ignorer la vérification TLS (certificat auto-signé du gateway)
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=data,
            stream=True,
            verify=False,
            timeout=30
        )
        
        logger.info(f"Response: {response.status_code} from {target_url}")
        
        # Retourner la réponse avec les mêmes headers (sauf certains)
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk
        
        return Response(
            stream_with_context(generate()),
            status=response.status_code,
            headers={
                (key, value) for key, value in response.headers.items()
                if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']
            }
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Proxy error: {e} for {target_url}")
        return {
            'error': 'proxy error',
            'message': str(e),
            'target_url': target_url
        }, 502

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'ok', 'target_app_id': TARGET_APP_ID, 'target_url': TARGET_BASE_URL}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
