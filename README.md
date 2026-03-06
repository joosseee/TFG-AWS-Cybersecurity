# 🛡️ TFG – Infraestructura Cloud Resiliente y Detección Heurística para Entornos Fintech

Repositorio que contiene el código fuente y la configuración técnica desarrollada como parte del **Trabajo de Fin de Grado (TFG) en Ingeniería/Ciberseguridad**.

El proyecto propone el diseño y despliegue de una **infraestructura cloud segura en Amazon Web Services (AWS)** para la organización ficticia **CloudFinance S.L.**, aplicando principios de **Zero Trust**, **defensa en profundidad** y los pilares del **AWS Well-Architected Framework**.

---

# 🚀 Arquitectura del Sistema

La arquitectura implementada integra múltiples servicios de AWS para proporcionar seguridad, escalabilidad y observabilidad.

### Componentes principales

**Backend Application**
- Servidor **EC2** ejecutando una aplicación Python.
- Framework **Flask** para la lógica web.
- **Gunicorn** como servidor WSGI.
- **NGINX** funcionando como proxy inverso.

**Gestión de Datos**
- **Amazon RDS (PostgreSQL)** para almacenamiento relacional.
- Base de datos ubicada en **subredes privadas** para mayor aislamiento.
- **Amazon S3** como repositorio de auditoría y almacenamiento de logs.
- Cifrado mediante **AWS KMS**.

**Seguridad Perimetral**
- **Application Load Balancer (ALB)** para distribución segura de tráfico.
- Segmentación de privilegios mediante **RBAC (Role-Based Access Control)**.
- Separación de accesos entre departamentos de **Finanzas** y **TI**.

---

# 🔍 Módulo de Detección Heurística y Threat Intelligence

El sistema incorpora una **capa de detección de anomalías basada en análisis de logs**, diseñada para identificar patrones de actividad maliciosa.

### Capacidades principales

**Detección heurística de anomalías**
- Evaluación de indicadores de riesgo por dirección IP.
- Generación de un **score de riesgo** basado en patrones sospechosos como:
  - intentos de fuerza bruta
  - scraping automatizado
  - enumeración de recursos
  - escalada de privilegios

**Análisis masivo de logs**
- Procesamiento de grandes volúmenes de eventos mediante **Amazon Athena**.
- Consultas SQL serverless sobre registros generados por:
  - **CloudFront**
  - **Application Load Balancer**
  - **AWS CloudTrail**

**Monitorización y respuesta**
- Panel interno de **SOC (Security Operations Center)**.
- Visualización cronológica de incidentes.
- Identificación de picos de ataques y patrones de bloqueo (ej. múltiples errores HTTP 401 / 403).

---

# 📂 Estructura del Proyecto
