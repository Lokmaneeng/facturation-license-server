"""
Serveur Flask pour la gestion des licences
Endpoints : /activate, /verify, /revoke, /status
"""
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import sqlite3
import json
import base64
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# Configuration
DB_PATH = os.getenv('DB_PATH', 'licenses.db')
PRIVATE_KEY_PATH = os.getenv('PRIVATE_KEY_PATH', 'keys/private.pem')
PUBLIC_KEY_PATH = os.getenv('PUBLIC_KEY_PATH', 'keys/public.pem')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', 'admin-secret-token-change-me')

# Charger les clés RSA
def load_private_key():
    """Charge la clé privée RSA"""
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key():
    """Charge la clé publique RSA"""
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

private_key = None
public_key = None

try:
    private_key = load_private_key()
    public_key = load_public_key()
    # Avoid Unicode symbols to prevent Windows cp1252 console errors
    print("[OK] Cles RSA chargees avec succes")
except Exception as e:
    print(f"[WARN] Erreur lors du chargement des cles : {e}")
    print("[WARN] Executez d'abord : python generate_keys.py")

# Decorator pour protéger les endpoints admin
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization header manquant'}), 401
        
        token = auth_header.split(' ')[1]
        if token != ADMIN_TOKEN:
            return jsonify({'error': 'Token invalide'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    """Connexion à la base de données"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_activation(license_key, hwid, success, reason=None, ip_address=None):
    """Enregistre une tentative d'activation"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO activation_logs (license_key, hwid, success, reason, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (license_key, hwid, 1 if success else 0, reason, datetime.now().isoformat(), ip_address))
    conn.commit()
    conn.close()

def sign_payload(payload_dict):
    """Signe un payload avec la clé privée RSA"""
    if not private_key:
        raise Exception("Clé privée non chargée")
    
    # Convertir le payload en JSON
    payload_json = json.dumps(payload_dict, sort_keys=True)
    payload_bytes = payload_json.encode('utf-8')
    
    # Signer avec RSA
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Encoder en base64
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    return payload_json, sig_b64

@app.route('/', methods=['GET'])
def home():
    """Page d'accueil du serveur"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Serveur de Licences - Application de Facturation Pro</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 900px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 {
                color: #4A90E2;
                border-bottom: 3px solid #4A90E2;
                padding-bottom: 10px;
            }
            h2 {
                color: #333;
                margin-top: 30px;
            }
            .status {
                padding: 15px;
                background: #e8f5e9;
                border-left: 4px solid #4caf50;
                margin: 20px 0;
            }
            .endpoint {
                background: #f9f9f9;
                padding: 10px;
                margin: 10px 0;
                border-left: 3px solid #2196f3;
            }
            code {
                background: #263238;
                color: #aed581;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }
            .method {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
                margin-right: 10px;
            }
            .post { background: #ff9800; color: white; }
            .get { background: #4caf50; color: white; }
            .warning {
                padding: 15px;
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Serveur de Licences</h1>
            <p><strong>Application de Facturation Pro v2.1.0</strong></p>
            
            <div class="status">
                ✅ <strong>Serveur actif et opérationnel</strong><br>
                🔑 Clés RSA : """ + ("✅ Chargées" if private_key else "❌ Non chargées") + """
            </div>
            
            <h2>📡 Endpoints Disponibles</h2>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/activate</code><br>
                <small>Active une licence pour une machine</small><br>
                <small>Body: <code>{"key": "FACT-2025-...", "hwid": "..."}</code></small>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/verify</code><br>
                <small>Vérifie une licence côté serveur</small><br>
                <small>Body: <code>{"key": "FACT-2025-...", "hwid": "..."}</code></small>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/status/&lt;key&gt;</code><br>
                <small>Retourne le statut d'une licence</small><br>
                <small>Exemple: <code>/status/DEMO-2025-FACT-APP1</code></small>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/revoke</code> 🔒 <small>(Admin)</small><br>
                <small>Révoque une licence</small><br>
                <small>Header: <code>Authorization: Bearer &lt;ADMIN_TOKEN&gt;</code></small><br>
                <small>Body: <code>{"key": "FACT-2025-..."}</code></small>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/logs</code> 🔒 <small>(Admin)</small><br>
                <small>Liste les logs d'activation</small><br>
                <small>Header: <code>Authorization: Bearer &lt;ADMIN_TOKEN&gt;</code></small>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/health</code><br>
                <small>Vérification santé du serveur</small>
            </div>
            
            <h2>🧪 Test Rapide</h2>
            <div class="warning">
                <strong>Test avec cURL :</strong><br><br>
                <code>curl -X POST """ + request.url_root + """activate -H "Content-Type: application/json" -d '{"key":"DEMO-2025-FACT-APP1","hwid":"test-123"}'</code>
            </div>
            
            <h2>📚 Documentation</h2>
            <p>
                • <a href="https://github.com/votre-repo/blob/main/license_server/README.md" target="_blank">Documentation serveur</a><br>
                • <a href="https://github.com/votre-repo/blob/main/client/README.md" target="_blank">Documentation client</a><br>
                • <a href="https://github.com/votre-repo/blob/main/LICENSE_SYSTEM_GUIDE.md" target="_blank">Guide complet</a>
            </p>
            
            <hr style="margin: 30px 0;">
            <p style="text-align: center; color: #999; font-size: 12px;">
                Serveur de Licences v1.0.0 • Octobre 2025
            </p>
        </div>
    </body>
    </html>
    """
    return html

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de santé"""
    return jsonify({
        'status': 'ok',
        'service': 'license-server',
        'keys_loaded': private_key is not None
    })

@app.route('/activate', methods=['POST'])
def activate():
    """
    Active une licence pour une machine spécifique
    Body: { "key": "<license-key>", "hwid": "<hardware-id>" }
    """
    data = request.get_json()
    
    if not data or 'key' not in data or 'hwid' not in data:
        return jsonify({'error': 'Paramètres manquants (key, hwid requis)'}), 400
    
    license_key = data['key'].strip().upper()
    hwid = data['hwid'].strip()
    client_ip = request.remote_addr
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Vérifier si la clé existe
    cursor.execute('SELECT * FROM licenses WHERE key = ?', (license_key,))
    license_row = cursor.fetchone()
    
    if not license_row:
        log_activation(license_key, hwid, False, "Clé inexistante", client_ip)
        conn.close()
        return jsonify({'error': 'Clé de licence invalide'}), 400
    
    license_dict = dict(license_row)
    
    # Vérifier si la licence est révoquée
    if license_dict['revoked']:
        log_activation(license_key, hwid, False, "Licence révoquée", client_ip)
        conn.close()
        return jsonify({'error': 'Licence révoquée'}), 403
    
    # Cas 1 : Licence déjà activée
    if license_dict['activated_hwid']:
        # Même machine → renvoyer le token
        if license_dict['activated_hwid'] == hwid:
            payload = {
                'key': license_key,
                'hwid': hwid,
                'client_name': license_dict['client_name'],
                'activated_at': license_dict['activated_at'],
                'revoked': False
            }
            
            payload_json, signature = sign_payload(payload)
            
            log_activation(license_key, hwid, True, "Réactivation sur même machine", client_ip)
            conn.close()
            
            return jsonify({
                'ok': True,
                'message': 'Licence déjà activée sur cette machine',
                'payload': payload_json,
                'signature': signature
            })
        else:
            # Machine différente → refuser
            log_activation(license_key, hwid, False, f"Déjà activée sur {license_dict['activated_hwid'][:8]}...", client_ip)
            conn.close()
            return jsonify({
                'error': 'Cette licence est déjà activée sur une autre machine',
                'activated_hwid': license_dict['activated_hwid'][:12] + '...'
            }), 403
    
    # Cas 2 : Première activation
    activated_at = datetime.now().isoformat()
    
    cursor.execute('''
        UPDATE licenses
        SET activated_hwid = ?, activated_at = ?
        WHERE key = ?
    ''', (hwid, activated_at, license_key))
    
    conn.commit()
    
    # Créer le payload signé
    payload = {
        'key': license_key,
        'hwid': hwid,
        'client_name': license_dict['client_name'],
        'activated_at': activated_at,
        'revoked': False
    }
    
    payload_json, signature = sign_payload(payload)
    
    log_activation(license_key, hwid, True, "Première activation", client_ip)
    conn.close()
    
    return jsonify({
        'ok': True,
        'message': 'Licence activée avec succès',
        'payload': payload_json,
        'signature': signature
    }), 200

@app.route('/verify', methods=['POST'])
def verify():
    """
    Vérifie une licence côté serveur
    Body: { "key": "<license-key>", "hwid": "<hardware-id>" }
    """
    data = request.get_json()
    
    if not data or 'key' not in data or 'hwid' not in data:
        return jsonify({'error': 'Paramètres manquants'}), 400
    
    license_key = data['key'].strip().upper()
    hwid = data['hwid'].strip()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM licenses WHERE key = ?', (license_key,))
    license_row = cursor.fetchone()
    conn.close()
    
    if not license_row:
        return jsonify({'valid': False, 'reason': 'Clé inexistante'}), 200
    
    license_dict = dict(license_row)
    
    if license_dict['revoked']:
        return jsonify({'valid': False, 'reason': 'Licence révoquée'}), 200
    
    if not license_dict['activated_hwid']:
        return jsonify({'valid': False, 'reason': 'Licence non activée'}), 200
    
    if license_dict['activated_hwid'] != hwid:
        return jsonify({'valid': False, 'reason': 'HWID ne correspond pas'}), 200
    
    return jsonify({
        'valid': True,
        'client_name': license_dict['client_name'],
        'activated_at': license_dict['activated_at']
    }), 200

@app.route('/revoke', methods=['POST'])
@require_admin
def revoke():
    """
    Révoque une licence (admin uniquement)
    Header: Authorization: Bearer <ADMIN_TOKEN>
    Body: { "key": "<license-key>" }
    """
    data = request.get_json()
    
    if not data or 'key' not in data:
        return jsonify({'error': 'Paramètre key manquant'}), 400
    
    license_key = data['key'].strip().upper()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT key FROM licenses WHERE key = ?', (license_key,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Clé inexistante'}), 404
    
    cursor.execute('UPDATE licenses SET revoked = 1 WHERE key = ?', (license_key,))
    conn.commit()
    conn.close()
    
    return jsonify({'ok': True, 'message': f'Licence {license_key} révoquée'}), 200

@app.route('/status/<key>', methods=['GET'])
def status(key):
    """
    Retourne le statut d'une licence
    """
    license_key = key.strip().upper()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM licenses WHERE key = ?', (license_key,))
    license_row = cursor.fetchone()
    conn.close()
    
    if not license_row:
        return jsonify({'error': 'Clé inexistante'}), 404
    
    license_dict = dict(license_row)
    
    return jsonify({
        'key': license_dict['key'],
        'client_name': license_dict['client_name'],
        'activated': license_dict['activated_hwid'] is not None,
        'activated_hwid': license_dict['activated_hwid'][:12] + '...' if license_dict['activated_hwid'] else None,
        'activated_at': license_dict['activated_at'],
        'revoked': bool(license_dict['revoked']),
        'created_at': license_dict['created_at']
    }), 200

@app.route('/logs', methods=['GET'])
@require_admin
def logs():
    """Liste les logs d'activation (admin uniquement)"""
    conn = get_db()
    cursor = conn.cursor()
    
    limit = request.args.get('limit', 100, type=int)
    
    cursor.execute('''
        SELECT * FROM activation_logs
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    logs_rows = cursor.fetchall()
    conn.close()
    
    logs_list = [dict(row) for row in logs_rows]
    
    return jsonify({'logs': logs_list, 'count': len(logs_list)}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    print(f"\n[START] Serveur de licences demarre sur le port {port}")
    print(f"[INFO] Base de donnees : {DB_PATH}")
    print(f"[INFO] Cle privee : {PRIVATE_KEY_PATH}")
    print(f"\nEndpoints disponibles :")
    print("  POST /activate - Activer une licence")
    print("  POST /verify   - Vérifier une licence")
    print("  POST /revoke   - Révoquer une licence (admin)")
    print("  GET  /status/<key> - Statut d'une licence")
    print("  GET  /logs     - Logs d'activation (admin)")
    print("  GET  /health   - Santé du serveur\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

