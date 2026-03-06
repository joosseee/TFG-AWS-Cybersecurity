TFG: Infraestructura Cloud Resiliente y Detección Heurística para Entornos Fintech
Este repositorio contiene el código fuente y la configuración técnica desarrollada como parte del Trabajo de Fin de Grado (TFG) en Ciberseguridad/Ingeniería. El proyecto aborda el diseño y despliegue de una infraestructura segura en Amazon Web Services (AWS) para la organización ficticia CloudFinance S.L., aplicando los pilares del AWS Well-Architected Framework y estrategias de defensa en profundidad.

🛡️ Módulo de Inteligencia de Amenazas y Detección Heurística
El proyecto implementa una capa de seguridad activa orientada a la detección temprana y el análisis forense utilizando Amazon Athena:

Detección heurística de anomalías: Evaluación de indicadores de riesgo para calcular una puntuación (score) por dirección IP, basándose en la identificación de patrones anómalos (intentos de fuerza bruta, scraping o escalada de privilegios).

Análisis masivo de registros (logs): Procesamiento de grandes volúmenes de eventos procedentes de CloudFront, Application Load Balancer (ALB) y CloudTrail mediante consultas SQL serverless.

Monitorización y alertado: El panel de administración SOC (Security Operations Center) proporciona visibilidad interactiva sobre los incidentes, trazando cronológicamente las ráfagas de ataques y los bloqueos (ej. errores HTTP 403/401 masivos).

🚀 Arquitectura Tecnológica
El despliegue en AWS (cuyas plantillas de infraestructura se han gestionado externamente) se apoya en los siguientes componentes integrados en este código:

Aplicación Backend: Servidor EC2 ejecutando Python (Flask y Gunicorn) con NGINX operando como proxy inverso.

Gestión de Datos: Almacenamiento relacional en Amazon RDS (PostgreSQL) ubicado en subredes privadas, y repositorios de auditoría en Amazon S3 protegidos mediante cifrado AWS KMS.

Seguridad Perimetral y de Acceso: Uso de Application Load Balancer (ALB) para la distribución segura del tráfico y un sistema de control de acceso basado en roles (RBAC) para segmentar los privilegios entre los departamentos de Finanzas y TI.

📂 Estructura del Código
app.py: Núcleo de la aplicación web. Orquesta la lógica de negocio, la autenticación de usuarios y el enrutamiento principal.

sec_heuristic.py: Módulo íntegro de inteligencia de amenazas. Contiene la lógica de conexión con AWS y las consultas estructuradas para la detección de anomalías.

templates/: Plantillas HTML del frontend, incluyendo internal.html (interfaz del Dashboard SOC para la visualización de incidentes).

static/: Recursos estáticos del lado del cliente (hojas de estilo CSS, scripts y recursos gráficos).

requirements.txt: Dependencias de Python necesarias para replicar el entorno de ejecución.

📌 Nota académica: Por motivos estrictos de seguridad y cumplimiento de las mejores prácticas, todas las credenciales, variables de entorno (.env), claves criptográficas y detalles específicos de la cuenta de AWS han sido excluidos de este repositorio público.
