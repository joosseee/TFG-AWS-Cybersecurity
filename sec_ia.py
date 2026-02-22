import os, io, time, boto3, pandas as pd
from botocore.config import Config
from flask import Blueprint, jsonify, request, abort

# Blueprint montado en /sec
bp = Blueprint("sec", __name__, url_prefix="/sec")

# Configuración desde variables de entorno
REGION          = os.getenv("AWS_REGION", "us-east-1")
ATHENA_DB       = os.getenv("ATHENA_DB", "sec_db")
ATHENA_OUTPUT   = os.getenv("ATHENA_S3_OUTPUT")
S3_BUCKET       = os.getenv("S3_BUCKET", "cloudfinance-bucket")
S3_KMS_KEY      = os.getenv("S3_KMS_KEY_ID")

# Clientes de AWS
athena = boto3.client("athena", region_name=REGION,
                      config=Config(retries={"max_attempts": 10}))
s3 = boto3.client("s3", region_name=REGION)

# --- Funciones Auxiliares ---

def run_athena(sql: str) -> pd.DataFrame:
    """Lanza la consulta en Athena y la devuelve como DataFrame."""
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": ATHENA_DB},
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT},
    )["QueryExecutionId"]

    while True:
        st = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if st in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1.2)

    if st != "SUCCEEDED":
        raise RuntimeError(f"Athena query failed: {st}")

    res = athena.get_query_results(QueryExecutionId=qid)
    cols = [c["Label"] for c in res["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
    rows = [[c.get("VarCharValue") for c in r["Data"]] for r in res["ResultSet"]["Rows"][1:]]
    return pd.DataFrame(rows, columns=cols)

def put_csv(df: pd.DataFrame, key: str) -> str:
    """Sube a S3 un CSV cifrado con KMS y devuelve presigned URL."""
    body = df.to_csv(index=False).encode()
    s3.put_object(
        Bucket=S3_BUCKET, Key=key, Body=body,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=S3_KMS_KEY,
        ContentType="text/csv"
    )
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=3600
    )

# --- Endpoints de Seguridad ---

@bp.get("/ping")
def ping():
    # Importación local para evitar bucle circular con app.py
    from app import current_groups
    roles_autorizados = {"admin-ti", "Analista-datos"}
    
    if not (current_groups() & roles_autorizados):
        return abort(403)
        
    return jsonify(ok=True, msg="sec blueprint listo")

@bp.get("/ip-sospechosas")
def ip_sospechosas():
    """Ranking de IPs por score en los últimos N minutos (CloudFront)."""
    # Verificación de Rol (SOC / Admin)
    from app import current_groups
    roles_autorizados = {"admin-ti", "Analista-datos"}
    if not (current_groups() & roles_autorizados):
        return abort(403)

    window = int(request.args.get("window", 60))
    top    = int(request.args.get("top", 20))

    sql = f"""
    WITH base AS (
      SELECT
        from_iso8601_timestamp(CONCAT(CAST(date AS VARCHAR),'T',time,'Z')) AS ts,
        -- Filtramos tanto vacíos como guiones para forzar el salto al siguiente valor
        coalesce(
            nullif(nullif(x_forwarded_for, '-'), ''), 
            nullif(c_ip, '-'), 
            'IP_Interna/Oculta'
        ) AS ip,
        sc_status,
        cs_uri_stem
      FROM cloudfront_logs
      WHERE from_iso8601_timestamp(CONCAT(CAST(date AS VARCHAR),'T',time,'Z'))
            >= now() - interval '{window}' minute
    ),
    agg AS (
      SELECT ip,
             count(*) AS reqs,
             sum(CASE WHEN sc_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS x4xx,
             approx_distinct(cs_uri_stem) AS uris
      FROM base
      GROUP BY ip
    )
    SELECT ip, reqs, x4xx, uris,
           (reqs/{max(window,1)}.0 + 2.0*x4xx + 0.5*uris) AS score
    FROM agg
    ORDER BY score DESC
    LIMIT {top};
    """

    df = run_athena(sql)
    items = [] if df.empty else df.to_dict(orient="records")
    url = key = None
    if not df.empty:
        key = f"informes/seguridad/ip_sospechosas_{int(time.time())}.csv"
        url = put_csv(df, key)
    return jsonify(ok=True, items=items, s3_key=key, download_url=url)


@bp.get("/spike-denegados")
def spike_denegados():
    """Serie temporal por minuto de AccessDenied en CloudTrail."""
    # Verificación de Rol (SOC / Admin)
    from app import current_groups
    roles_autorizados = {"admin-ti", "Analista-datos"}
    if not (current_groups() & roles_autorizados):
        return abort(403)

    window = int(request.args.get("window", 1440))

    sql = f"""
    WITH base AS (
      SELECT from_iso8601_timestamp(eventtime) AS ts
      FROM cloudtrail_logs
      WHERE from_iso8601_timestamp(eventtime) >= (now() - interval '{window}' minute)
        AND errorCode IN ('AccessDenied','Client.UnauthorizedOperation','UnauthorizedOperation')
    )
    SELECT 
        format_datetime(date_trunc('minute', ts), 'HH:mm') AS minuto, 
        count(*) AS denegados
    FROM base
    GROUP BY 1
    ORDER BY 1 DESC;
    """

    df = run_athena(sql)
    series = [] if df.empty else df.to_dict(orient="records")
    url = key = None
    if not df.empty:
        key = f"informes/seguridad/spike_denegados_{int(time.time())}.csv"
        url = put_csv(df, key)
    return jsonify(ok=True, series=series, s3_key=key, download_url=url)