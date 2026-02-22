# app.py — CloudFinance (FIX: CSP + perfil phone + ensure cliente on login)
import os, io, csv, math, datetime, hashlib, base64, re, hmac, logging
from secrets import token_urlsafe
from urllib.parse import urlparse, urljoin
from urllib.parse import quote_plus
from functools import wraps
from datetime import timedelta
from typing import Optional
from datetime import datetime, timezone
from flask import (
    Flask, jsonify, request, redirect, url_for, session, abort, send_from_directory,render_template
)
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from botocore.config import Config
import boto3, psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

# ========= Config (.env) =========a
load_dotenv(".env")

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "5"))

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET  = os.getenv("S3_BUCKET")
S3_ENCRYPTION = (os.getenv("S3_ENCRYPTION") or "AES256").strip()  # "AES256" o "aws:kms"
S3_KMS_KEY_ID = (os.getenv("S3_KMS_KEY_ID") or "").strip()

COGNITO_REGION     = os.getenv("COGNITO_REGION", "us-east-1")
USER_POOL_ID       = os.getenv("COGNITO_USER_POOL_ID")
APP_CLIENT_ID      = os.getenv("COGNITO_APP_CLIENT_ID")
APP_CLIENT_SECRET  = (os.getenv("COGNITO_CLIENT_SECRET") or "").strip()  # vacío => público (PKCE)

REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
POST_LOGOUT_REDIRECT_URI = os.getenv("POST_LOGOUT_REDIRECT_URI", "http://localhost:8000/")


API_KEY = os.getenv("API_KEY", "")

# ========= Flask =========
app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET") or os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
app.config.update(
    SESSION_COOKIE_NAME="cf_session",
    SESSION_COOKIE_DOMAIN=None,            # imprescindible en localhost
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # True en prod
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024, # 2 MiB
    PREFERRED_URL_SCHEME="https",   
)
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
logging.basicConfig(level=logging.INFO)


# ========= IA modulo =========
from sec_ia import bp as sec_bp
app.register_blueprint(sec_bp)



# ========= AWS =========
s3 = boto3.client(
    "s3", 
    region_name=AWS_REGION, 
    config=Config(signature_version='s3v4')
)
cognito = boto3.client("cognito-idp", region_name=COGNITO_REGION)

# ========= DB (pool simple) =========
POOL: Optional[SimpleConnectionPool] = None
def _pool():
    global POOL
    if POOL is None:
        POOL = SimpleConnectionPool(
            minconn=1, maxconn=max(1, DB_POOL_MAX),
            host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            port=DB_PORT, sslmode="require",
        )
    return POOL

def db_select(q, p=()):
    pool = _pool(); conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(q, p)
            return cur.fetchall()
    finally:
        pool.putconn(conn)

def db_exec(q, p=()):
    pool = _pool(); conn = pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(q, p)
    finally:
        pool.putconn(conn)

# ========= OAuth (Cognito) =========
oauth = OAuth(app)
AUTHORITY = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}"
oauth.register(
    name="oidc",
    client_id=APP_CLIENT_ID,
    client_secret=APP_CLIENT_SECRET or None,
    server_metadata_url=f"{AUTHORITY}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile phone"},
)

# ========= Utilidades =========
def _pkce_pair():
    v = token_urlsafe(64)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    return v, c

def _is_safe_url(target: str) -> bool:
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return (test.scheme in ("http","https")) and (ref.netloc == test.netloc)

def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def _s3_put_csv(key: str, body: bytes):
    params = {"Bucket": S3_BUCKET, "Key": key, "Body": body, "ContentType": "text/csv"}
    if S3_ENCRYPTION.lower() == "aws:kms":
        params.update({"ServerSideEncryption": "aws:kms"})
        if S3_KMS_KEY_ID:
            params.update({"SSEKMSKeyId": S3_KMS_KEY_ID})
    else:
        params.update({"ServerSideEncryption": "AES256"})
    try:
        s3.put_object(**params)
    except Exception as e:
        print(f"DEBUG S3 ERROR: {e}")
        raise e
def presign_get(key, exp=3600):
    return s3.generate_presigned_url("get_object", Params={"Bucket": S3_BUCKET, "Key": key}, ExpiresIn=exp)

# CSV safe: evita fórmulas (Excel/Sheets)
def _csv_cell(x):
    s = "" if x is None else str(x)
    return "'" + s if s[:1] in ("=","+","-","@") else s

# ========= Session helpers =========
def current_user():
    return session.get("user") or {}

def current_groups():
    claims = session.get("id_token_claims") or {}
    g = claims.get("cognito:groups", [])
    if isinstance(g, str):
        g = [x.strip() for x in g.split(",") if x.strip()]
    return set(g or [])

def current_email():
    claims = session.get("id_token_claims") or {}
    return claims.get("email") or current_user().get("email")

def current_cliente_id():
    """Deriva cliente_id por email (modelo email-only)."""
    email = current_email()
    if not email:
        return None
    r = db_select("SELECT id FROM clientes WHERE email=%s", (email,))
    return r[0]["id"] if r else None

def login_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not current_user() and not session.get("id_token_claims"):
            return redirect(url_for("login", next=request.url))
        return fn(*a, **kw)
    return w

def require_groups(*needed):
    needed = set(needed)
    def deco(fn):
        @wraps(fn)
        def w(*a, **kw):
            if not (current_groups() & needed):
                return abort(403)
            return fn(*a, **kw)
        return w
    return deco

def require_api_key():
    if not API_KEY:
        return None
    return None if request.headers.get("X-API-Key") == API_KEY else ("Forbidden", 403)

def log_access(recurso, accion):
    u = current_user() or {}
    email = u.get("email")
    usuario_id = None
    if email:
        r = db_select("SELECT id FROM usuarios_internos WHERE email=%s", (email,))
        if r: usuario_id = r[0]["id"]
    db_exec(
        "INSERT INTO accesos_logs (usuario_id, recurso, accion, ip_origen) VALUES (%s,%s,%s,%s)",
        (usuario_id, recurso, accion, _client_ip())
    )

# ========= Seguridad HTTP =========
@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Permitimos inline JS temporalmente para compat con cliente.html/internal.html
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return resp

# ========= Health =========
@app.get("/health")
def health():
    out = {"status": "ok"}
    try:
        db_select("SELECT 1")
        out["db"] = "ok"
    except Exception as e:
        out["db"] = f"error:{e.__class__.__name__}"
    try:
        s3.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
        out["s3"] = "ok"
    except Exception as e:
        out["s3"] = f"error:{e.__class__.__name__}"
    return jsonify(out)

# ========= Home =========
# ========= Home (CON PLANTILLA) =========
@app.get("/")
def index():
    u = current_user()
    is_staff = False
    is_client = False
    
    if u:
        # 1. Obtenemos los grupos de Cognito del usuario actual
        groups = current_groups() # Esta función debe devolver un set o lista de grupos
        
        # 2. Definimos quiénes son Staff para el TFG
        staff_roles = {"admin-ti", "Analista-datos", "finanzas-lectura", "Finanzas-lectura"}
        
        # 3. Verificamos si el usuario pertenece a alguno de esos grupos
        is_staff = bool(groups & staff_roles)
        
        # 4. Verificamos si tiene un cliente_id (es cliente)
        is_client = current_cliente_id() is not None
    
   
    # IMPORTANTE: Enviamos las variables al HTML
    return render_template("index.html", 
                           user=u, 
                           is_staff=is_staff, 
                           is_client=is_client)


    

# ========= Auth (PKCE + nonce, email verificado) =========
COGNITO_SCOPES = os.getenv("COGNITO_SCOPES",
    "openid email profile phone aws.cognito.signin.user.admin")

@app.get("/login")
def login():
    ver, chal = _pkce_pair()
    session.clear()
    session["pkce_verifier"] = ver
    nonce = token_urlsafe(16)
    session["oidc_nonce"] = nonce
    next_url = request.args.get("next")
    if next_url and _is_safe_url(next_url):
        session["post_login_next"] = next_url
    return oauth.oidc.authorize_redirect(
        REDIRECT_URI,
        scope=COGNITO_SCOPES,          # ⬅️ importante
        code_challenge=chal,
        code_challenge_method="S256",
        nonce=nonce,
    )

@app.get("/callback")
def callback():
    ver = session.pop("pkce_verifier", None)
    token = oauth.oidc.authorize_access_token(code_verifier=ver)

     # --- DEBUG: mira qué scopes trae el access token ---
    try:
        from base64 import urlsafe_b64decode
        import json
        at = token.get("access_token", "")
        payload = at.split(".")[1] + "=="
        scopes = json.loads(urlsafe_b64decode(payload)) .get("scope", "")
        app.logger.info(f"AccessToken scopes: {scopes}")
        if "phone" not in scopes.split():
            app.logger.warning("AccessToken sin scope 'phone'; actualizar teléfono fallará.")
    except Exception:
        pass
    # --- fin DEBUG -


    # Valida id_token (iss/aud/exp/nonce) y obtén claims
    claims = oauth.oidc.parse_id_token(token, nonce=session.pop("oidc_nonce", None)) or {}
    # UserInfo (opcional)
    try:
        userinfo = oauth.oidc.userinfo(token=token) or {}
    except Exception:
        userinfo = {}

    # Requiere email verificado
    email_verified = claims.get("email_verified")
    if isinstance(email_verified, str):
        email_verified = email_verified.lower() == "true"
    if not claims.get("email") or email_verified is not True:
        session.clear()
        return ("Se requiere email verificado en Cognito.", 403)

    session.permanent = True
    session["id_token_claims"] = dict(claims)
    session["user"] = dict(userinfo)
    session["access_token"] = token.get("access_token")

    # === FIX: asegura que exista fila en 'clientes' para el modelo email-only ===
    try:
        email = claims.get("email")
        nombre = (userinfo.get("name") or claims.get("name") 
                  or (email.split("@")[0] if email else ""))
        if email:
            db_exec("""
                INSERT INTO clientes (nombre, email)
                VALUES (%s, %s)
                ON CONFLICT (email) DO NOTHING
            """, (nombre, email))
    except Exception as e:
        app.logger.warning(f"No se pudo asegurar cliente en BD: {e}")

    next_url = session.pop("post_login_next", None)
    return redirect(next_url if next_url and _is_safe_url(next_url) else url_for("index"))




@app.get("/logout")
def logout():
    session.clear()
    meta = oauth.oidc.load_server_metadata()
    
    # Derivamos el endpoint de logout de Cognito
    auth_ep = meta["authorization_endpoint"]
    base = auth_ep.rsplit("/oauth2/", 1)[0]
    logout_url = f"{base}/logout"
    
    # LIMPIEZA TOTAL: .strip() quita espacios del .env y quote_plus codifica la URL
    safe_logout_uri = quote_plus(POST_LOGOUT_REDIRECT_URI.strip())
    
    # Construcción de la URL de salida oficial de AWS
    final_logout_path = f"{logout_url}?client_id={APP_CLIENT_ID}&logout_uri={safe_logout_uri}"
    
    return redirect(final_logout_path)

# ========= Portal interno =========
@app.get("/internal")
@login_required
# He añadido 'finanzas-lectura' en minúscula también para mayor seguridad
@require_groups("admin-ti", "Analista-datos", "Finanzas-lectura", "finanzas-lectura")
def internal_home():
    return render_template("internal.html", groups=list(current_groups()))
# ========= Movimientos / Informes (interno) =========
@app.get("/movimientos")
@login_required
@require_groups("admin-ti", "Analista-datos", "finanzas-lectura","Finanzas-lectura")
def movimientos():
    try:
        limit  = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except Exception:
        limit, offset = 50, 0
    rows = db_select("""
        SELECT id, cliente, tipo_operacion, cantidad, fecha
        FROM v_movimientos
        ORDER BY fecha DESC
        LIMIT %s OFFSET %s
    """, (limit, offset))
    total = db_select("SELECT COUNT(*) AS c FROM movimientos_financieros")[0]["c"]
    log_access("RDS", f"SELECT v_movimientos limit={limit} offset={offset}")
    return jsonify({
        "total": total, "limit": limit, "offset": offset,
        "pages": math.ceil(total/limit) if limit else 1,
        "data": [{
            "id": r["id"], "cliente": r["cliente"], "tipo": r["tipo_operacion"],
            "cantidad": float(r["cantidad"]), "fecha": r["fecha"].isoformat() if r["fecha"] else None
        } for r in rows]
    })

@app.get("/informes")
@login_required
@require_groups("admin-ti", "Analista-datos", "finanzas-lectura","Finanzas-lectura")
def listar_informes():
    # Consultamos la vista que une Informes con Clientes
    rows = db_select("""
        SELECT id, cliente, s3_path, tipo_informe, fecha_generado
        FROM v_informes
        ORDER BY fecha_generado DESC
        LIMIT 100
    """)
    out = []
    for r in rows:
        try:
            # Generamos la URL solo si el archivo existe y tenemos permisos
            url = presign_get(r["s3_path"], 3600)
        except Exception as e:
            app.logger.error(f"Error presigning {r['s3_path']}: {e}")
            url = None
            
        out.append({
            "id": r["id"],
            "cliente": r["cliente"],
            "s3_key": r["s3_path"],
            "tipo_informe": r["tipo_informe"],
            "fecha": r["fecha_generado"].isoformat() if r["fecha_generado"] else None,
            "download_url": url # Si es null, el frontend mostrará "no disponible"
        })
    return jsonify(out)



@app.post("/informes/generar")
@login_required
@require_groups("admin-ti", "Analista-datos", "finanzas-lectura","Finanzas-lectura")
def generar_informe():
    # 1. Obtenemos datos del body JSON
    data = request.get_json(silent=True) or {}
    cliente_nombre = (data.get("cliente") or "").strip()
    tipo = (data.get("tipo") or "contable").strip()

    # 2. Búsqueda HEURÍSTICA: Evitamos fallos por tildes o mayúsculas
    cliente_id = None
    if cliente_nombre:
        r = db_select("SELECT id FROM clientes WHERE nombre ILIKE %s", (f"%{cliente_nombre}%",))
        cliente_id = r[0]["id"] if r else None

    if not cliente_id:
        return jsonify({"error": f"No se encontró el cliente '{cliente_nombre}'. Revisa el nombre exacto."}), 404

    # 3. Consultamos movimientos en RDS
    rows = db_select("""
        SELECT id, tipo_operacion, cantidad, fecha 
        FROM movimientos_financieros 
        WHERE cliente_id = %s 
        ORDER BY fecha DESC LIMIT 200
    """, (cliente_id,))

    if not rows:
        return jsonify({"error": "Este cliente no tiene movimientos registrados."}), 400

    # 4. Generamos el CSV en memoria
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "tipo_operacion", "cantidad", "fecha"])
    for x in rows:
        w.writerow([
            _csv_cell(x["id"]),
            _csv_cell(x["tipo_operacion"]),
            _csv_cell(float(x["cantidad"])),
            _csv_cell(x["fecha"].isoformat() if x["fecha"] else "")
        ])

    # 5. Definimos la ruta en S3 CUMPLIENDO con la política de prefijos
    # Usamos 'processed/' para que la política de IAM permita el acceso
    prefix = f"processed/informes/clientes/{cliente_id}"
    key = f"{prefix}/informe_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"

    try:
        # Subida cifrada a S3 (SSE-KMS según tu .env)
        _s3_put_csv(key, buf.getvalue().encode("utf-8"))
        
        # Guardamos en la tabla para que aparezca en el dashboard
        db_exec("INSERT INTO informes (cliente_id, s3_path, tipo_informe) VALUES (%s,%s,%s)", 
                (cliente_id, key, tipo))
        
        # Auditoría de acceso
        log_access("S3", f"GENERATE_REPORT {key}")
        
        return jsonify({
            "status": "success",
            "s3_key": key, 
            "download_url": presign_get(key, 3600)
        }), 201
        
    except Exception as e:
        print(f"DEBUG S3 ERROR: {e}") # Para verlo en la terminal de EC2
        return jsonify({"error": "Error de permisos en S3 (IAM/KMS). Verifique logs."}), 500


@app.get("/export/csv")
@login_required
@require_groups("admin-ti", "Analista-datos", "finanzas-lectura","Finanzas-lectura")
def export_csv():
    rows = db_select("""
        SELECT id, cliente, tipo_operacion, cantidad, fecha
        FROM v_movimientos
        ORDER BY fecha DESC
    """)
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["id","cliente","tipo_operacion","cantidad","fecha"])
    for r in rows:
        w.writerow([
            _csv_cell(r["id"]),
            _csv_cell(r["cliente"]),
            _csv_cell(r["tipo_operacion"]),
            _csv_cell(float(r["cantidad"])),
            _csv_cell(r["fecha"].isoformat() if r["fecha"] else "")
        ])
    key = f"processed/exports/informe_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    _s3_put_csv(key, buf.getvalue().encode("utf-8"))
    log_access("S3", f"PUT {key}")
    return {"s3_key": key, "download_url": presign_get(key, 3600)}, 201



# ========= Portal cliente =========
@app.get("/cliente")
@login_required
def cliente_home():
    cid = current_cliente_id()
    if not cid:
        return "No asociado a cliente. Contacte con soporte.", 403
    return send_from_directory(app.static_folder, "cliente.html")

@app.get("/cliente/movimientos")
@login_required
def cliente_movs():
    cid = current_cliente_id()
    if not cid: return abort(403)
    try:
        limit  = min(int(request.args.get("limit", 100)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except Exception:
        limit, offset = 100, 0
    rows = db_select("""
        SELECT id, tipo_operacion, cantidad, fecha
        FROM movimientos_financieros
        WHERE cliente_id = %s
        ORDER BY fecha DESC
        LIMIT %s OFFSET %s
    """, (cid, limit, offset))
    total = db_select("SELECT COUNT(*) AS c FROM movimientos_financieros WHERE cliente_id=%s", (cid,))[0]["c"]
    log_access("RDS", f"SELECT movimientos cliente_id={cid}")
    return jsonify({
        "total": total, "limit": limit, "offset": offset,
        "pages": math.ceil(total/limit) if limit else 1,
        "data": [{
            "id": r["id"], "tipo": r["tipo_operacion"],
            "cantidad": float(r["cantidad"]),
            "fecha": r["fecha"].isoformat() if r["fecha"] else None
        } for r in rows]
    })

@app.post("/cliente/movimientos/nuevo")
@login_required
def cliente_nuevo_mov():
    cid = current_cliente_id()
    if not cid: return abort(403)
    d = request.get_json(force=True) or {}
    tipo = (d.get("tipo_operacion") or "").strip()[:64]
    try:
        cantidad = float(d.get("cantidad"))
    except Exception:
        return ("'cantidad' debe ser numérico", 400)
    fecha = d.get("fecha")
    if fecha:
        try: datetime.datetime.fromisoformat(fecha.replace("Z","+00:00"))
        except Exception: return ("'fecha' debe ser ISO 8601", 400)
    db_exec("""
        INSERT INTO movimientos_financieros(cliente_id, tipo_operacion, cantidad, fecha)
        VALUES (%s,%s,%s, COALESCE(%s, NOW()))
    """, (cid, tipo, cantidad, fecha))
    log_access("RDS", f"INSERT movimientos cliente_id={cid}")
    return {"ok": True}, 201

@app.get("/cliente/informes")
@login_required
def cliente_informes():
    cid = current_cliente_id()
    if not cid: return abort(403)
    rows = db_select("""
      SELECT id, s3_path, tipo_informe, fecha_generado
      FROM informes
      WHERE cliente_id = %s
      ORDER BY fecha_generado DESC
      LIMIT 100
    """, (cid,))
    out = []
    for r in rows:
        try: url = presign_get(r["s3_path"], 1800)
        except Exception: url = None
        out.append({
            "id": r["id"], "s3_key": r["s3_path"],
            "tipo_informe": r["tipo_informe"],
            "fecha": r["fecha_generado"].isoformat() if r["fecha_generado"] else None,
            "download_url": url
        })
    log_access("S3", f"LIST informes cliente_id={cid}")
    return jsonify(out)

# ========= Perfil (clientes) =========
def client_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.url))
        if not current_cliente_id():
            return ("Solo disponible para clientes.", 403)
        return fn(*a, **kw)
    return w

@app.get("/perfil")
@login_required
@client_required
def perfil_get():
    u = current_user() or {}
    # Escapa por si acaso
    email = (u.get("email") or "").replace("<","&lt;").replace(">","&gt;")
    phone = (u.get("phone_number")
             or (session.get("id_token_claims") or {}).get("phone_number")
             or "")
    cid = current_cliente_id()
    csrf = token_urlsafe(32)
    session["csrf_token"] = csrf
    return f"""
    <!doctype html><html lang="es"><head><meta charset="utf-8"><title>Perfil</title>
    <style>body{{font-family:system-ui,Arial;margin:2rem;max-width:640px}}</style></head>
    <body>
      <h1>Mi perfil (cliente_id={cid})</h1>
      <p><b>Email:</b> {email}</p>
      <form method="post" action="/perfil">
        <input type="hidden" name="csrf_token" value="{csrf}" />
        <label>Teléfono (formato E.164, ej. +34600123456)</label><br/>
        <input name="phone" value="{phone}" style="width:320px;padding:.4rem" />
        <div style="margin-top:1rem">
          <button type="submit" style="padding:.5rem 1rem">Guardar</button>
          <a href="/" style="margin-left:1rem">Volver</a>
        </div>
      </form>
    </body></html>
    """

@app.post("/perfil")
@login_required
@client_required
def perfil_post():
    # --- CSRF ---
    sent = (request.form.get("csrf_token") or "")
    token_csrf = session.pop("csrf_token", "")
    if not token_csrf or not hmac.compare_digest(sent, token_csrf):
        return ("CSRF token inválido", 400)

    # --- Validación de teléfono (E.164 simple) ---
    phone = (request.form.get("phone") or "").strip()
    if phone and not re.fullmatch(r"^\+\d{8,15}$", phone):
        return ("Formato de teléfono no válido. Usa + prefijo y dígitos, ej. +34600123456", 400)

    # --- Actualiza Cognito usando SOLO el AccessToken del usuario ---
    acc = session.get("access_token")
    if not acc:
        # fuerza re-login para obtener un Access Token válido con scopes actualizados
        return redirect(url_for("login", next=url_for("perfil_get")))
    try:
        if phone:
            cognito.update_user_attributes(
                AccessToken=acc,
                UserAttributes=[{"Name": "phone_number", "Value": phone}]
            )
        else:
            # eliminar el atributo si el campo viene vacío
            cognito.delete_user_attributes(
                AccessToken=acc,
                UserAttributeNames=["phone_number"]
            )
    except cognito.exceptions.NotAuthorizedException as e:
        # El AccessToken ha caducado o no es válido.
        app.logger.warning(f"AccessToken caducado, redirigiendo a login: {e}")
        # Redirigimos al login pasando 'next' para que vuelva al perfil tras loguearse
        return redirect(url_for("login", next=url_for("perfil_get")))
    except cognito.exceptions.InvalidParameterException as e:
        app.logger.error(f"Parámetro inválido al actualizar phone_number: {e}")
        return ("Formato de teléfono no válido para Cognito.", 400)
    except Exception as e:
        app.logger.error(f"Error actualizando phone_number en Cognito: {e}")
        return ("No se pudo actualizar el teléfono en Cognito.", 500)

    # --- Refleja en sesión para que se vea al volver a /perfil ---
    session.setdefault("user", {})["phone_number"] = phone
    session.setdefault("id_token_claims", {})["phone_number"] = phone

    # --- Actualiza BBDD por email (best-effort) ---
    try:
        email = current_email()
        if email:
            db_exec("UPDATE clientes SET telefono=%s WHERE email=%s", (phone, email))
    except Exception as e:
        app.logger.error(f"Error actualizando teléfono en BBDD: {e}")

    return redirect(url_for("perfil_get"))



@app.get("/debug/trigger-iam-error")
@login_required
@require_groups("admin-ti", "Analista-datos") # Asegúrate de las mayúsculas/minúsculas correctas
def trigger_iam_error():
    """
    Intenta CREAR un usuario administrador. Esto fallará seguro y generará el AccessDenied.
    """
    try:
        # Usamos IAM, que es un servicio global y muy restringido
        iam = boto3.client("iam", region_name="us-east-1")
        
        # Intentamos crear un usuario (Acción de escritura crítica)
        iam.create_user(UserName="Hacker_Simulado_TFG")
        
        return "⚠️ ¡ALERTA! Tu servidor tiene permisos para crear usuarios. Esto es un fallo de seguridad real."
        
    except Exception as e:
        # ESTO ES LO QUE QUEREMOS: Que falle y entre aquí.
        app.logger.info(f"Ataque simulado exitoso (AccessDenied generado): {e}")
        return jsonify({
            "status": "Ataque Simulado Correctamente",
            "tipo_error": "AccessDenied (IAM:CreateUser)",
            "mensaje_aws": str(e)
        })
# ========= Run (dev) =========
if __name__ == "__main__":
    # En prod: gunicorn -b 127.0.0.1:8000 app:app
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "8000")), debug=True)
