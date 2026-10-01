# Experiments

El endpoint `POST /api/experiments/run` ejecuta ataques sobre una credencial almacenada y persiste cada resultado en SQLite. Compara:

- A_CONTROL: QR sin firma, control de integridad.
- B_FIRMA: QR + Ed25519.
- C_PROPUESTA: QR + Ed25519 + metadata de shares/LSB.

El tiempo de cada caso es medido con `perf_counter`. Un ataque de payload alterado debe invalidar la firma en B y C. A no puede demostrar autenticidad porque deliberadamente es el control. Los ataques de compresion, ruido, recorte, pixelado e impresion requieren imagenes reales capturadas y no se rellenan con valores aleatorios. La exportacion JSON esta disponible en la respuesta del endpoint y CSV en `/api/experiments/export.csv`.
Con esto se determinará que opción es la más segura.
