# Authorization Lifecycle Audit API — report-only

**Estado:** integrado de forma opcional y no bloqueante en el validador Python.

La auditoría se activa mediante el input opcional `authorization-evidence-path`, que apunta a un archivo JSON dentro del workspace. El archivo usa el fixture de fase 1: un objeto con `now_utc` opcional y una lista `cases`; cada caso contiene `name`, `consumed_text`, `evidence` y `policy`.

> La auditoría responde qué estados tiene la evidencia de autorización; no afirma que un pago x402, una firma o un recibo autoricen por sí solos el cumplimiento posterior.

## Uso

```yaml
- uses: smartflowproai-lang/x402-endpoint-validator@main
  with:
    endpoints: '["https://api.example.com/resource"]'
    authorization-evidence-path: '.github/x402/authorization-evidence.json'
    fail-on: 'any'
```

El resultado aparece en `endpoints[*].checks.authorization_evidence`. La configuración ausente devuelve `state: not_configured`. Un archivo ilegible o una evidencia inválida se reporta como `structurally_invalid`, pero todas las salidas mantienen `blocking: false`.

| Campo | Significado |
|---|---|
| `enabled` | Indica si se proporcionó un bundle local. |
| `blocking` | Siempre `false` en esta fase; es una garantía explícita de compatibilidad. |
| `passed` | `true` sólo si todos los casos son `valid_and_authorized`; no participa en el cálculo de `endpoints[*].passed`. |
| `state_counts` | Conteo reproducible por estado. |
| `case_results` | Estado y razones por caso, sin descargar `authorization_uri`. |
| `source` | Ruta local del bundle usado. |

## Límites de seguridad

La integración no hace solicitudes para resolver URI, no ejecuta criptografía de esquemas, no modifica `validator.py` en su camino de decisión x402, no altera `summary.all_passed`, no cambia los códigos de salida y no envía pagos, pedidos ni secretos. La ruta de datos se limita a leer el JSON local y calcular la clasificación pura existente.

Los cinco estados de la fase son `structurally_invalid`, `structurally_valid_zero_authority`, `valid_and_authorized`, `expired` y `revoked`. Un futuro modo bloqueante requeriría una decisión de producto independiente, un perfil de política explícito y pruebas adicionales; no está implementado aquí.

## Validación

La prueba de integración cubre el modo desactivado, el bundle de seis casos, errores de lectura y la invariancia de `endpoint.passed` cuando la auditoría contiene estados no autorizados. La suite existente permanece separada y debe seguir pasando con el mismo comportamiento.

## Referencias

[1]: https://github.com/crisnovillo1991/agent-receipt-spec/issues/14 "Agent Receipt Spec issue #14"
[2]: https://docs.x402.org/extensions/payment-identifier "x402 Payment-Identifier"
[3]: https://docs.x402.org/extensions/offer-receipt "x402 Signed Offers & Receipts"
