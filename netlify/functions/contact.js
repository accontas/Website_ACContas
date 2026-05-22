// ═══════════════════════════════════════════════════════════════
// netlify/functions/contact.js
// Backend seguro para o formulário de contacto da ACContas
//
// Fluxo: Browser → esta Function → Make.com webhook
// A API key e URL do webhook NUNCA chegam ao browser.
// ═══════════════════════════════════════════════════════════════

exports.handler = async function (event) {
  // ── 1. Só aceita POST ───────────────────────────────────────
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: JSON.stringify({ error: "Método não permitido" }) };
  }

  // ── 2. Ler variáveis de ambiente (definidas no painel Netlify) ──
  const WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;
  const API_KEY     = process.env.MAKE_API_KEY;

  if (!WEBHOOK_URL || !API_KEY) {
    console.error("❌ Variáveis de ambiente em falta: MAKE_WEBHOOK_URL ou MAKE_API_KEY");
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Configuração do servidor incompleta" }),
    };
  }

  // ── 3. Validação dos dados recebidos (server-side) ──────────
  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) };
  }

  const { nome, email, telefone, servico, mensagem, _honeypot } = body;

  // Detetar bots via honeypot (campo invisível no formulário)
  if (_honeypot && _honeypot.trim() !== "") {
    console.warn("🚨 Bot detetado (honeypot preenchido)");
    // Responder 200 para não alertar o bot
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  }

  // Validações de campos obrigatórios
  const erros = [];
  if (!nome || nome.trim().length < 3)
    erros.push("Nome deve ter pelo menos 3 caracteres");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    erros.push("Email inválido");
  if (!telefone || !/^\d{9}$/.test(telefone.replace(/\s/g, "")))
    erros.push("Telefone deve ter 9 dígitos");
  if (!servico || servico.trim() === "")
    erros.push("Selecione um serviço");
  if (!mensagem || mensagem.trim().length < 10)
    erros.push("Mensagem deve ter pelo menos 10 caracteres");

  if (erros.length > 0) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: erros.join(". ") }),
    };
  }

  // ── 4. Enviar para o Make.com de forma segura ───────────────
  const payload = {
    nome:      nome.trim(),
    email:     email.trim().toLowerCase(),
    telefone:  telefone.trim(),
    servico:   servico.trim(),
    mensagem:  mensagem.trim(),
    timestamp: new Date().toISOString(),
    origem:    "accontas.pt",
  };

  try {
    const response = await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-make-apikey": API_KEY,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      console.error(`❌ Make.com respondeu com status ${response.status}`);
      throw new Error(`Make.com error: ${response.status}`);
    }

    console.log("✅ Lead enviado para Make.com:", payload.email);
    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, message: "Pedido enviado com sucesso" }),
    };
  } catch (err) {
    console.error("❌ Erro ao contactar Make.com:", err.message);
    return {
      statusCode: 502,
      body: JSON.stringify({ error: "Erro ao processar o pedido. Tente novamente." }),
    };
  }
};
