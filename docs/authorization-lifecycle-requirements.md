# Authorization Lifecycle Audit — matriz de requisitos de fase 2

> **Estado:** artefacto de diseño y pruebas. Este documento no incorpora el contrato al núcleo de x402 ni modifica todavía `validator.py`, `action.yml`, los códigos de salida o el comportamiento de CI.

## Fuente y límites

La matriz transforma en requisitos verificables la especificación local de fase 1 y la propuesta de disciplina de transporte discutida en el issue #14 de Agent Receipt Spec. El issue es una propuesta abierta: sus campos se usan para alinear el perfil experimental, no como afirmación de que ya son obligatorios para x402. [1]

| ID | Requisito comprobable | Evidencia de cumplimiento actual | Veredicto de fase 2 | Próximo punto de integración |
|---|---|---|---|---|
| AL-01 | El hash debe corresponder a los **bytes exactos consumidos**, sin reserialización JSON. | `authorization_evidence.py` compara SHA-256 de `consumed_bytes`; fixture y 64 mutaciones deterministas lo cubren. | Implementado en módulo aislado. | `checks.authorization_evidence.integrity` report-only. |
| AL-02 | La estructura debe incluir referencia de decisión, URI, hash, esquema, referencia de verificador, transporte, firma, estado y vigencia. | `REQUIRED_EVIDENCE_FIELDS` y prueba de campo faltante. | Implementado en módulo aislado. | Adaptador de evidencia, sin hacer fetch del URI. |
| AL-03 | Una firma no exitosa no concede integridad ni autoridad. | Fixture `signature_invalid`. | Implementado en módulo aislado. | Adaptador de verificación por esquema, futuro. |
| AL-04 | La revocación debe ser terminal después de pasar integridad y estructura. | Fixture `revoked_evidence` y propiedad de tres políticas. | Implementado en módulo aislado. | Estado durable del merchant/consumer, fuera de x402 core. |
| AL-05 | La expiración no autoriza, incluso con clave y esquema permitidos. | Fixture `expired_evidence` y propiedad de límite exacto. | Implementado en módulo aislado. | Reporte de vigencia. |
| AL-06 | La autoridad depende de una política local explícita de esquema y clave. | Fixture de clave no autorizada y prueba de política parcial/ausente. | Implementado en módulo aislado. | Archivo o entrada opt-in de política. |
| AL-07 | Una política ausente o incompleta debe producir cero autoridad, nunca confianza implícita. | Prueba `test_absent_or_partial_policy_never_grants_authority`. | Implementado en módulo aislado. | Revisión focalizada de defaults en fase 3. |
| AL-08 | La nueva auditoría no debe alterar la conformidad x402 existente ni el resultado de CI durante su fase informativa. | No se modificaron `validator.py`, `action.yml`, endpoints, pagos ni códigos de salida. | Implementado como restricción de alcance. | Integración sólo tras una prueba de regresión dedicada. |
| AL-09 | El perfil no debe descargar URIs ni realizar llamadas de red durante una ejecución de CI. | El módulo acepta bytes explícitos y documenta la ausencia de recuperación remota. | Implementado como restricción de diseño. | Los adaptadores remotos requerirán una fase y autorización separadas. |

## Método de verificación

La matriz aplica el método de cumplimiento especificación-a-código con un alcance reducido. Cada requisito se vincula a una línea de enforcement y, cuando corresponde, a una fixture o prueba determinista. Ningún requisito se marca como obligatorio para x402 hasta que exista una decisión de estándar independiente.

| Veredicto | Significado en este repositorio |
|---|---|
| Implementado en módulo aislado | La lógica y pruebas existen, pero aún no intervienen en una ejecución normal del validador. |
| Pendiente de integración report-only | El requisito tiene contrato y pruebas, pero necesita un punto opt-in de lectura/reporte. |
| Fuera de alcance | Depende de un verificador criptográfico, de estado durable de una parte de negocio o de una decisión de estándar. |

## Puertas antes de conectar el reporte

La futura conexión con `validator.py` debe conservar los siguientes límites: la entrada tiene que ser explícitamente opt-in; toda salida debe clasificarse sin modificar `passed`; los problemas de evidencia deben reflejarse como hallazgos informativos; y la validación de endpoints x402 debe ejecutar las mismas pruebas de regresión actuales. Las adaptaciones criptográficas por esquema se evaluarán por separado, sin implementar primitivas criptográficas propias.

## Referencias

[1]: https://github.com/crisnovillo1991/agent-receipt-spec/issues/14 "Agent Receipt Spec issue #14 — First-class authorization field with transport discipline"
