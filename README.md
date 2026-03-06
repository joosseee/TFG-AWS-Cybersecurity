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
- **Amazon CloudFront** como CDN y primera capa de exposición pública, proporcionando distribución global del contenido, optimización del tráfico y una capa adicional de protección frente a picos de solicitudes junto a cifrado TLS en las comunicaciones.
- **Application Load Balancer (ALB)** para la distribución segura del tráfico hacia los servicios backend.
- Segmentación de privilegios mediante **RBAC (Role-Based Access Control)**.
- Separación de accesos entre departamentos de **Finanzas** y **TI**.


---
# 📡 Monitorización, Auditoría y Respuesta ante Incidentes

La infraestructura incorpora servicios nativos de AWS orientados a la **observabilidad, auditoría de seguridad y detección temprana de incidentes**, permitiendo supervisar el entorno cloud y reaccionar ante comportamientos anómalos.

---

## 🔎 Auditoría de Actividad

### AWS CloudTrail

Se utiliza **AWS CloudTrail** para registrar todas las acciones realizadas dentro de la cuenta AWS, incluyendo:

- llamadas a la API
- accesos a recursos
- cambios en configuraciones
- actividad administrativa

Este servicio proporciona **trazabilidad completa de las operaciones**, permitiendo realizar auditorías de seguridad y análisis forense ante posibles incidentes.

Los logs generados por CloudTrail se almacenan en **Amazon S3**, garantizando persistencia, integridad y disponibilidad para su posterior análisis mediante **Amazon Athena**.

---

## 📊 Monitorización de Infraestructura

### Amazon CloudWatch

**Amazon CloudWatch** se emplea para recopilar métricas del sistema y analizar eventos generados por los distintos servicios de AWS.

Entre sus funciones principales se incluyen:

- monitorización de métricas de infraestructura
- análisis de logs del sistema
- detección de anomalías en el comportamiento de los servicios

Se han configurado **CloudWatch Alarms** que monitorizan eventos críticos como:

- picos de errores HTTP
- incremento de intentos de autenticación fallidos
- actividad inusual en recursos cloud

Estas alarmas permiten activar mecanismos de respuesta temprana ante posibles amenazas.

---

## 🚨 Sistema de Alertas

### Amazon Simple Notification Service (SNS)

**Amazon SNS** actúa como sistema de **notificación centralizado** para alertar al equipo de seguridad cuando se detectan eventos sospechosos.

Las alarmas generadas por **CloudWatch** envían notificaciones a un **SNS Topic**, que posteriormente distribuye alertas a los administradores del sistema mediante:

- correo electrónico
- integraciones externas de monitorización

Esto permite una **respuesta rápida por parte del equipo de seguridad**, reduciendo el tiempo de detección y reacción ante incidentes.


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


# 📂 Estructura del Proyecto

├── app.py
├── sec_ia.py
├── templates/
│ └── internal.html
│ └── index.html
├── static/
│ ├── cliente.html
├── requirements.txt
├── config-ssh.txt
└── README.md


### Descripción de los componentes

**app.py**

Núcleo de la aplicación web. Gestiona:

- autenticación de usuarios
- lógica de negocio
- enrutamiento principal

**sec_ia.py**

Módulo de detección de amenazas que incluye:

- conexión con AWS
- consultas Athena
- análisis heurístico de eventos

**templates/**

Plantillas HTML utilizadas por la aplicación.


**static/**

Recursos del lado cliente

**requirements.txt**

Listado de dependencias necesarias para ejecutar la aplicación.

**config-ssh.txt**

Configuración SSH para conectar servidor EC2 con VisualStudio


# ⚙️ Tecnologías Utilizadas

- **Python**
- **Flask**
- **Gunicorn**
- **NGINX**
- **AWS EC2**
- **AWS RDS (PostgreSQL)**
- **AWS S3**
- **AWS CloudTrail**
- **AWS Athena**
- **AWS KMS**



# 📊 Objetivo del Proyecto

El objetivo del proyecto es demostrar cómo una infraestructura cloud puede integrar:

- **principios de Zero Trust**
- **defensa en profundidad**
- **observabilidad de seguridad**
- **detección temprana de anomalías**

todo ello dentro de un entorno reproducible basado en **AWS**.


# 🔐 Nota de Seguridad

Por motivos de seguridad y buenas prácticas, **no se incluyen en este repositorio**:

- credenciales
- claves criptográficas
- variables de entorno (`.env`)
- identificadores de cuenta AWS
- configuraciones sensibles de infraestructura

La infraestructura fue desplegada mediante plantillas externas de automatización y configuraciones específicas de entorno.


# 🎓 Contexto Académico

Este proyecto ha sido desarrollado como parte del **Trabajo de Fin de Grado en Ingenieria de la ciberseguridad**, centrado en el diseño de arquitecturas cloud seguras y sistemas de detección de anomalías basados en análisis de logs.


