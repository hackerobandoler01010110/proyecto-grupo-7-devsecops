// metadata-mock.js - Simula el endpoint interno de metadatos de un proveedor de nube
// (equivalente a http://169.254.169.254/latest/meta-data/ en AWS)
// Se usa SOLO para demostrar el SSRF del endpoint /imagenes/descargar de forma controlada,
// sin consultar infraestructura real de ningun proveedor de nube.

const express = require('express');
const app = express();
const PORT = 9999;

app.get('/latest/meta-data/', (req, res) => {
  res.json({
    'iam/security-credentials': 'propnet-role',
    'instance-id': 'i-0demo1234567890',
    'local-ipv4': '127.0.0.1',
  });
});

app.get('/latest/meta-data/iam/security-credentials/propnet-role', (req, res) => {
  res.json({
    AccessKeyId: 'AKIA-DEMO-FAKE',
    SecretAccessKey: 'demo-secret-no-es-real',
    Token: 'demo-token',
  });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Mock de metadatos de nube escuchando en http://127.0.0.1:${PORT}`);
});
