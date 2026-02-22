# TFG-AWS-Cybersecurity
# CloudFinance - Plataforma Financiera Segura con IA en AWS

**Trabajo de Fin de Grado (TFG)**
**Tecnologías:** Python (Flask), AWS (Athena,EC2,KMS,Cloudwatch,CloudTrail,SNS,RDS, CloudFront, ALB, Elastic IP, VPC, Security Groups, IAM, Cognito, S3 Buckets), Inteligencia de Seguridad.

## 📋 Descripción del Proyecto
Este repositorio contiene el código fuente de una plataforma financiera de alta seguridad diseñada para la nube. El sistema integra un **Módulo de Inteligencia de Seguridad (SIEM)** capaz de detectar amenazas en tiempo real analizando patrones de tráfico y logs de auditoría.

## 🧠 Módulo de IA y Seguridad (Security Analytics)
El proyecto implementa una capa de defensa proactiva utilizando **Amazon Athena** y análisis de comportamiento:
* **Detección de Anomalías:** Algoritmos que puntúan (*scoring*) el riesgo de cada IP basándose en patrones de acceso (fuerza bruta, escaneos de puertos).
* **Análisis de Logs en Tiempo Real:** Procesamiento de terabytes de logs de **AWS WAF** y **CloudTrail** mediante consultas SQL serverless.
* **Respuesta Automatizada:** El panel de administración alerta visualmente sobre intentos de intrusión (Códigos 403/401 masivos).

## 🚀 Arquitectura Tecnológica
El despliegue en AWS (infraestructura gestionada externamente) incluye:
* **Backend:** Servidor EC2 con Python Flask y Gunicorn usando NGINX como proxy inverso.
* **Datos:** RDS PostgreSQL (Subnet Privada) y S3 con cifrado KMS.
* **Seguridad Perimetral:** Balanceador de Carga (ALB).
* **Control de Acceso:** Sistema RBAC (Role-Based Access Control) granular para departamentos de Finanzas y TI.

## 📂 Estructura del Código
* `app.py`: Núcleo de la aplicación. Orquesta la lógica de negocio y las consultas de seguridad.
* `templates/internal.html`: **Dashboard SOC**. Interfaz que visualiza los ataques detectados por Athena.
* `static/`: Recursos del lado del cliente.
* `aws-config/`: (Opcional) Políticas JSON de IAM y definiciones del Dashboard.

---
*Nota académica: Las credenciales, variables de entorno (.env) y la infraestructura de IA se han abstraído de este repositorio por motivos de seguridad.*
