# Authorization Lifecycle Audit v0 — contrato de evidencia

**Estado:** propuesta de fase 1. **Ámbito:** fixtures, clasificación pura y pruebas locales. Este documento no modifica x402, no cambia el comportamiento de `validator.py` y no activa ningún bloqueo de CI.

## Propósito

Una respuesta x402 y una liquidación prueban que se cotizó o movió valor; no prueban que un merchant siga autorizado para cumplir una acción después de una cancelación, reembolso, expiración o cambio de política. Esta capa propone evidencia verificable para que un consumidor distinga tres conceptos que deben permanecer separados: integridad de los bytes consumidos, validez estructural de la evidencia y autoridad de la clave bajo su propia política local.

El diseño toma como referencia el issue #14 de Agent Receipt Spec para el vínculo de bytes de transporte y la separación entre validez estructural y autoridad. No declara ese issue como parte de la especificación base de x402 ni impone un esquema de firma concreto.

## Forma de evidencia

La evidencia de fase 1 es un objeto JSON que contiene una decisión, una referencia recuperable, el hash de los bytes exactos consumidos y metadatos suficientes para que un futuro adaptador de esquema verifique la firma.

| Campo | Requerido | Significado de fase 1 |
|---|---:|---|
| `decision_ref` | Sí | Identificador lógico de la decisión previa a la acción. |
| `authorization_uri` | Sí | Ubicación declarada de la evidencia; fase 1 no la descarga. |
| `authorization_sha256` | Sí | SHA-256 hexadecimal de los bytes exactos que se verificaron. |
| `scheme` | Sí | Identificador del esquema de autorización o verificación. |
| `verifier_key_ref` | Sí | Referencia de una clave para descubrimiento o verificación estructural. |
| `transport_hint` | Sí | Uno de `raw_url`, `relay_event`, `bundle` u `other`. |
| `signature_valid` | Sí | Resultado booleano de un adaptador de verificación; fase 1 lo recibe como dato fixture. |
| `status` | Sí | `active` o `revoked`. |
| `valid_until` | Sí | Límite temporal UTC canónico de la decisión. |

## Clasificación

| Estado | Condición | Interpretación |
|---|---|---|
| `structurally_invalid` | Campos ausentes, firma inválida, hash distinto o forma no admitida. | No usar la evidencia. |
| `structurally_valid_zero_authority` | Hash y estructura pasan, pero la política local no acepta el esquema o la clave. | La evidencia puede ser real, pero no está autorizada para este consumidor. |
| `valid_and_authorized` | Integridad, estructura, vigencia, esquema y clave aceptada pasan. | La evidencia satisface la política local actual. |
| `expired` | La evidencia íntegra y estructuralmente válida ya excedió `valid_until`. | No reutilizar para una nueva acción. |
| `revoked` | La evidencia íntegra y estructuralmente válida registra revocación terminal. | Resultado seguro y explícito; no es un error de parsing. |

Una firma que verifica no autoriza por sí misma. `verifier_key_ref` identifica la clave; la política del consumidor decide si dicha clave es aceptable. Una misma evidencia debe poder cambiar de `structurally_valid_zero_authority` a `valid_and_authorized` sólo al cambiar la política local, no los bytes firmados.

## Límites de seguridad

La implementación de fase 1 no hace solicitudes de red, no resuelve URI, no ejecuta criptografía de esquema, no toca encabezados x402, no paga endpoints, no crea pedidos y no activa checkout físico. Las fases posteriores deberán introducir adaptadores por esquema, una política explícita de confianza, tolerancia de reloj y una integración sandbox con tombstones de cancelación o reembolso antes de cualquier modo bloqueante.

La eventual integración con `validator.py` debe seguir el precedente de Bazaar: informar `checks.authorization_evidence` sin modificar `passed` ni códigos de salida. Sólo un perfil de política futuro y explícitamente activado podría elevar determinados estados a advertencias o fallos.

## Fixtures de esta fase

`tests/fixtures/authorization_evidence_cases.json` cubre evidencia autorizada, hash incorrecto, expiración, revocación, clave sin autoridad y firma inválida. Los hashes se calculan sobre bytes estáticos de fixture, no sobre una serialización JSON reconstruida durante la clasificación.

## Referencias

[1]: https://github.com/crisnovillo1991/agent-receipt-spec/issues/14 "First-class authorization field with transport discipline (v0.3)"
[2]: https://docs.x402.org/extensions/payment-identifier "Payment-Identifier (Idempotency)"
[3]: https://docs.x402.org/extensions/offer-receipt "Signed Offers & Receipts"

## Validación de fase 1

La implementación aislada y sus fixtures se validaron localmente el 14 de agosto de 2026 mediante `python3 -m unittest -v tests/test_authorization_evidence.py` y la suite completa `python3 -m unittest discover -s tests -v`. Ambas ejecuciones finalizaron correctamente; la suite completa informó **74 pruebas aprobadas**. Ningún archivo de integración de pagos, de red o de ejecución de `validator.py` fue modificado por esta fase.

## Validación de fase 2

La fase 2 añadió cobertura de propiedades determinista sin dependencias nuevas. La prueba muta 64 variantes de un byte del caso autorizado y confirma que ninguna conserva integridad; también confirma que revocación, expiración y políticas ausentes o parciales nunca conceden autoridad. El 14 de agosto de 2026, `python3 -m unittest -v tests/test_authorization_evidence.py tests/test_authorization_evidence_properties.py` y `python3 -m unittest discover -s tests -v` terminaron correctamente; la suite completa informó **78 pruebas aprobadas**. La fase continúa aislada: `validator.py` y `action.yml` no fueron modificados.
