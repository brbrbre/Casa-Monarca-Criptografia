# Casa Monarca
## Criptografía e Identidades Digitales
*Narrativa del Desarrollo — Bitácora de Sesiones*

MA2006B — Uso de Álgebras Modernas para Seguridad y Criptografía

Tecnológico de Monterrey · Equipo 1 · Grupo 602 · 2026

---

## Acto I: Los Cimientos
*Sesiones 1–3: Diseño e Investigación*

### Sesión 1: El Problema

Cuando comenzó el reto, entendimos como equipo que Casa Monarca A.C., una organización humanitaria que atiende migrantes, maneja información extremadamente sensible sin protección criptográfica. El desafío era diseñar una solución PKI (Infraestructura de Clave Pública) que fuera segura y que respetara el contexto real de la organización.

**Los primeros pasos fueron fundamentales:**

- Establecer cómo citar correctamente las herramientas criptográficas utilizadas (PyCA 2026, autor y año)
- Documentar el flujo ejecutable del código
- Anclar cada componente a la realidad de Casa Monarca: la Certificate Authority no es abstracta, es Python sobre sus sistemas específicos

**Entregables de la semana:**

- Citas actualizadas con autor y año
- Demos de código ejecutable con output real
- Diagramas mapeados a infraestructura de Casa Monarca

---

### Sesión 2: Restricciones técnicas

La investigación reveló restricciones como el que Casa Monarca operaba con MySQL 5.7 y CryptoSSLeay, infraestructura legacy que el equipo tenía que respetar. Nuestras metas de la semana fueron:

- Actualizar Figure 1 con componentes reales de Casa Monarca
- Explicar Figure 3 (el flujo end-to-end) como un producto cohesivo
- Listar cómo se conectan los componentes, enfocándose en el gestor de identidades

---

### Sesión 3: El Primer Obstáculo

En esta sesión la conexión con MySQL era importante. Surgieron además preguntas organizacionales que no eran técnicas, pero sí relevantes: ¿cómo se da de alta a los colaboradores? ¿Autoservicio o administrador? ¿Necesitaba aprobación de la OSF para ejecutar un modelo híbrido? Nuestros enfoques fueron:

- Demostración de almacenamiento y bases de datos funcionales
- Plan de operación híbrida aprobado por la OSF

---

## Acto II: Construyendo la Identidad
*Sesiones 4–7: Sistema de Identidades*

### Sesión 4: Decisiones sobre Certificados

Una semana llena de preguntas que definieron la arquitectura:

- **¿Quién tiene certificado?** Solo niveles admin y coordinadores. Operativos y voluntarios usan otras mecánicas.
- **¿Cuál es el ciclo de vida?** Emisión → Uso → Revocación → Expiración. Cada transición documentada.
- **¿Cómo se distribuye?** Como el SAT: en USB, con privacidad, con mecanismos de recuperación.

---

### Sesión 5: El Producto

El equipo trazó el flujo: colaboradores reciben USB con su `.cert` y `.key`, los migrantes se registran de otra manera. La visión era *small steps*.

**Entregable: Crear un usuario desde cero hasta que tenga su certificado listo y documentar el backend en el reporte técnico.**

---

### Sesión 6: Mostrar los Datos, No Guardar Archivos

Un cambio de perspectiva: en lugar de guardar certificados en PDF, decidimos desplegar los datos directamente en la interfaz (Name, Issuer, Serial Number, Dates). La información debe ser verificable y no solo descargable. El PDF puede perderse o modificarse.

---

### Sesión 7: Cerrando la Brecha

Con la validación de campos en formularios avanzando y la tabla de pruebas casi lista, surgió la pregunta de contingencia: ¿Qué pasa si el admin desaparece? El equipo necesitaba un plan de emergencia. Nuestros enfoques fueron:

- Tabla de pruebas de certificados completada
- Demo en vivo: crear coordinador desde cero

---

## Acto III: Escalando a Registros
*Sesiones 8–13: Sistema de Registros y ARCO*

### Sesión 8: Pausa y Validación

Los casos de prueba fueron enviados al profesor sin comentarios de regreso. El equipo tomó un momento para hacer pruebas de funcionamiento.

---

### Sesión 9: Certificados

Los certificados ahora tenían que funcionar realmente. El sistema necesitaba validar que el Name en el certificado coincidiera con quién estaba firmando. Teníamos las siguientes rutas críticas:

- Descarga de `.key` y `.cert` en el onboarding del coordinador
- Certificado revocado vs. certificado expirado: flujos distintos, consecuencias distintas
- Etiquetas e hipervínculos en tabla de pruebas, ligados a evidencia

---

### Sesiones 10–12: El Gestor de Registros

Con identidades establecidas, era la hora de proteger los datos de los migrantes. El sistema implementa CRUD diferenciado por nivel:

| Nivel | Permisos |
|---|---|
| Admin | Create, Read, Update, Delete |
| Coordinador | Create, Read, Update |
| Operativo | Create, Read |
| Voluntario | Create (solo formulario) |

La firma se realiza al completar cada registro. La clave privada se carga una sola vez, se usa, y se descarta de memoria. El log registra **todos** los pasos y solo el admin puede verlo.

---

### Sesión 13: Privacidad, Cadena de Mando y ARCO

Dos elementos se priorizaron en esta sesión:

- **Aviso de Privacidad** integrado en todo formulario, cumpliendo LFPDPPP
- **Firmas en paralelo:** todos los niveles firman el mismo hash simultáneamente. El hash determina el orden, no el tiempo.

Derechos ARCO (Acceso, Rectificación, Cancelación, Oposición) con lógica de escalamiento:

- Acceso y Rectificación: flujo Operativo → Coordinador
- Cancelación: sube directamente hasta el Admin

---

## Acto IV: Refinamiento y Presentación
*Sesiones 14–17: Polish, Demo y Entrega Final*

### Sesión 14: Depuración

El CRUD aún tenía errores. El equipo revisó cada flujo cuidadosamente, manejó excepciones, y se preparó para la demostración del viernes. No se avanza sin validar.

---

### Sesión 15: Cambio de Planes

Una decisión crítica simplificó la cadena de custodia:

- Corrección de flujo CRUD
- Implementar ARCO completo

---

### Sesión 16: Pre-Entrega

La última semana de trabajo. Nos enfocamos en los detalles siguientes:

- Lista de usuarios y contraseñas para pruebas (documento separado, nunca en código)
- Carpeta con certificados y keys organizada y lista para distribuir
- Formularios mejorados para parecerse lo más posible a la realidad de migrantes
- Argumentación legal explícita de cada paso ARCO y LFPDPPP
- Verificación al eliminar migrante: confirmación obligatoria antes de cualquier borrado

**Calendario de entrega:**

- Jueves 11:00 — Reportes finales entregados
- Viernes 11:00 — Presentación completa ante el grupo

---

### Sesión 17: El Final

En los últimos días, nos enfocamos en:

- Setup completo con perfiles inventados con historias reales para hacer la demo comprensible para cualquier persona, no solo para técnicos.

---

Después de 17 sesiones de desarrollo colaborativo, el equipo entregó:

- **Una PKI funcional**
- **Sistema de identidades** (ciclo de vida completo de certificados X.509)
- **Gestor de registros migrantes** (con CRUD diferenciado, firma y auditoría)
- **Derechos ARCO** (acceso, rectificación, cancelación, oposición con trazabilidad legal)

---
