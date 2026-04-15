/*
 * Custom .shield rules example — inline rules plus custom block response.
 *
 * Start:  node examples/express-custom-rules.js
 * Test:   curl http://localhost:3000/admin
 */

const express = require('express');
const shieldwall = require('../src/index');

const app = express();
app.use(express.json());

const customRules = `
// block access to admin paths — adapt to your application
rule block_admin_access : custom {
    meta:
        author      = "MyApp"
        description = "Block unauthorized admin panel access attempts"
        severity    = "high"

    target:
        $url = request.url

    strings:
        $admin = /\\/(admin|wp-admin|phpmyadmin|adminer|manager)\\/?\$/i
        $api   = /\\/api\\/admin/i

    condition:
        $admin in $url or $api in $url
}

// detect web shell upload attempts
rule webshell_upload : custom {
    meta:
        author      = "MyApp"
        description = "Detects server-side code injection in request body"
        severity    = "critical"

    target:
        $body = request.body

    strings:
        $php  = /(<\\?php|<\\?=).*\\b(eval|exec|system|passthru|shell_exec)\\s*\\(/i
        $jsp  = /Runtime\\.getRuntime\\(\\)\\.exec/i
        $asp  = /Server\\.CreateObject.*WScript\\.Shell/i

    condition:
        $php in $body or $jsp in $body or $asp in $body
}
`;

app.use(shieldwall({
  mode: 'block',
  logLevel: 'debug',
  customRules,
  blockMessage: (matches) => JSON.stringify({
    error: 'Blocked by ShieldWall',
    rules: matches.map(m => ({ rule: m.rule, reason: m.description })),
  }),
}));

app.get('/', (req, res) => res.json({ message: 'Protected with custom rules' }));
app.get('/admin', (req, res) => res.json({ message: 'Admin panel' }));
app.post('/upload', (req, res) => res.json({ status: 'uploaded' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Custom rules example at http://localhost:${PORT}`);
  console.log(`Test: curl http://localhost:${PORT}/admin\n`);
});
