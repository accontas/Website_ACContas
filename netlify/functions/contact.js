// ═══════════════════════════════════════════════════════════════
// netlify/functions/contact.js
// Backend seguro do formulário de contacto — ACContas
//
// Segurança implementada:
//  • API key e webhook URL em variáveis de ambiente (nunca no browser)
//  • Validação server-side completa
//  • Rate limiting por IP (máx 5 pedidos / hora)
//  • Honeypot anti-bot
//  • Verificação do header Origin
//  • Sanitização de inputs
// ═══════════════════════════════════════════════════════════════

// Armazenamento em memória para rate limiting por IP
// (reinicia a cada deploy — aceitável para o volume de um site pessoal)
const ipRateLimits = new Map();
const RATE_LIMIT_MAX      = 5;       // máx pedidos por janela
const RATE_LIMIT_WINDOW   = 3600000; // 1 hora em ms

function checkIpRateLimit(ip) {
  const now    = Date.now();
  const record = ipRateLimits.get(ip) || { count: 0, firstRequest: now };

  // Reset da janela se passou mais de 1 hora
  if (now - record.firstRequest > RATE_LIMIT_WINDOW) {
    ipRateLimits.set(ip, { count: 1, firstRequest: now });
    return true;
  }

  if (record.count >= RATE_LIMIT_MAX) return false;

  record.count++;
  ipRateLimits.set(ip, record);
  return true;
}

// Sanitizar texto — remove HTML e limita comprimento
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .slice(0, maxLen)
    .trim();
}

exports.handler = async function (event) {
  // ── 1. Preflight CORS ───────────────────────────────────────
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, body: '' };
  }

  // ── 2. Só aceita POST ───────────────────────────────────────
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Método não permitido' }) };
  }

  // ── 3. Verificar Origin (impede chamadas de outros domínios) ─
  const origin   = event.headers['origin'] || '';
  const referer  = event.headers['referer'] || '';
  const validOrigins = ['https://accontas.pt', 'https://www.accontas.pt'];

  // Em desenvolvimento local (netlify dev) não há origin — permite
  const isDev = origin === '' && referer === '';
  if (!isDev && !validOrigins.some(o => origin.startsWith(o) || referer.startsWith(o))) {
    console.warn('🚨 Origin inválido:', origin, referer);
    return { statusCode: 403, body: JSON.stringify({ error: 'Acesso não autorizado' }) };
  }

  // ── 4. Rate limiting por IP ─────────────────────────────────
  const ip = event.headers['x-forwarded-for']?.split(',')[0]?.trim()
          || event.headers['x-nf-client-connection-ip']
          || 'unknown';

  if (!checkIpRateLimit(ip)) {
    console.warn('⏳ Rate limit atingido para IP:', ip);
    return {
      statusCode: 429,
      headers: { 'Retry-After': '3600' },
      body: JSON.stringify({ error: 'Demasiados pedidos. Tente novamente em 1 hora.' }),
    };
  }

  // ── 5. Variáveis de ambiente ────────────────────────────────
  const WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;
  const API_KEY     = process.env.MAKE_API_KEY;

  if (!WEBHOOK_URL || !API_KEY) {
    console.error('❌ Variáveis de ambiente em falta');
    return { statusCode: 500, body: JSON.stringify({ error: 'Configuração do servidor incompleta' }) };
  }

  // ── 6. Parse do body ────────────────────────────────────────
  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'Pedido inválido' }) };
  }

  const { nome, email, telefone, servico, mensagem, _honeypot } = body;

  // ── 7. Honeypot ─────────────────────────────────────────────
  if (_honeypot && _honeypot.trim() !== '') {
    console.warn('🤖 Bot detetado (honeypot)');
    return { statusCode: 200, body: JSON.stringify({ ok: true }) }; // Silencioso
  }

  // ── 8. Validação server-side ────────────────────────────────
  const erros = [];
  if (!nome     || nome.trim().length < 3)               erros.push('Nome inválido');
  if (!email    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) erros.push('Email inválido');
  if (!telefone || !/^\d{9}$/.test(telefone.replace(/\s/g, ''))) erros.push('Telefone inválido');
  if (!servico  || servico.trim() === '')                erros.push('Serviço não selecionado');
  if (!mensagem || mensagem.trim().length < 10)          erros.push('Mensagem demasiado curta');

  if (erros.length > 0) {
    return { statusCode: 400, body: JSON.stringify({ error: erros.join('. ') }) };
  }

  // ── 9. Sanitizar e preparar payload ─────────────────────────
  const payload = {
    nome:      sanitize(nome, 100),
    email:     sanitize(email, 200).toLowerCase(),
    telefone:  sanitize(telefone, 20),
    servico:   sanitize(servico, 100),
    mensagem:  sanitize(mensagem, 2000),
    timestamp: new Date().toISOString(),
    origem:    'accontas.pt',
    ip_hash:   ip.slice(0, 8) + '***', // Parcial para RGPD
  };

  // ── 10. Enviar para Make.com ─────────────────────────────────
  try {
    const response = await fetch(WEBHOOK_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-make-apikey': API_KEY,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      console.error(`❌ Make.com respondeu ${response.status}`);
      throw new Error(`Make.com error: ${response.status}`);
    }

    console.log('✅ Lead enviado:', payload.email, '| IP:', ip.slice(0, 8) + '***');
    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, message: 'Pedido enviado com sucesso' }),
    };
  } catch (err) {
    console.error('❌ Erro ao contactar Make.com:', err.message);
    return {
      statusCode: 502,
      body: JSON.stringify({ error: 'Erro ao processar o pedido. Tente novamente.' }),
    };
  }
};
