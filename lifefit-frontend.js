const LIFEFIT_AUTH_API = "https://lifefitt.onrender.com/api/auth";
const LIFEFIT_TERMS_VERSION = "1.0";

const legalText = {
  terms: `
    <h2>Termos de Uso — LifeFIT</h2>
    <p>Versão ${LIFEFIT_TERMS_VERSION}</p>
    <h3>1. Aceitação</h3>
    <p>Ao criar uma conta ou usar o LifeFIT, você concorda com estes Termos e com a Política de Privacidade.</p>
    <h3>2. Uso do serviço</h3>
    <p>O LifeFIT oferece receitas, preferências e ferramentas de planejamento alimentar. O conteúdo é informativo e não substitui orientação médica ou nutricional.</p>
    <h3>3. Conta</h3>
    <p>Você é responsável pelas informações fornecidas e por manter sua conta protegida.</p>
    <h3>4. Alterações</h3>
    <p>Podemos atualizar estes termos e solicitar novo aceite para uma versão nova.</p>
  `,
  privacy: `
    <h2>Política de Privacidade — LifeFIT</h2>
    <p>Versão ${LIFEFIT_TERMS_VERSION}</p>
    <h3>1. Dados tratados</h3>
    <p>Tratamos nome, e-mail, método de login, foto de perfil quando disponível e os dados que você decidir salvar no LifeFIT.</p>
    <h3>2. Finalidade</h3>
    <p>Usamos seus dados para autenticar sua conta, personalizar recursos e manter o serviço seguro.</p>
    <h3>3. Login social</h3>
    <p>Google e Facebook informam apenas os dados autorizados por você. O LifeFIT não armazena tokens sociais no navegador.</p>
    <h3>4. Seus direitos</h3>
    <p>Você pode solicitar acesso, correção ou exclusão dos seus dados pelo canal de contato do LifeFIT.</p>
  `
};

function installLegalStyle() {
  if (document.getElementById("lifefit-legal-style")) return;

  const style = document.createElement("style");
  style.id = "lifefit-legal-style";
  style.textContent = `
    .legal-overlay {
      position: fixed;
      inset: 0;
      z-index: 3000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: rgba(12,43,33,.58);
    }
    .legal-overlay.show { display: flex; }
    .legal-dialog {
      position: relative;
      width: min(720px, 100%);
      max-height: 85vh;
      overflow: auto;
      border-radius: 16px;
      padding: 32px;
      background: var(--creme, #fff);
      box-shadow: 0 22px 50px rgba(0,0,0,.2);
    }
    .legal-dialog h2 { font-family: var(--serif, serif); }
    .legal-dialog h3 { margin: 22px 0 6px; }
    .legal-dialog p { margin-bottom: 12px; }
    .legal-close {
      position: absolute;
      top: 12px;
      right: 15px;
      border: 0;
      background: none;
      font-size: 24px;
    }
  `;
  document.head.appendChild(style);
}

window.openLegal = function (type) {
  installLegalStyle();

  let overlay = document.getElementById("lifefit-legal");

  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "lifefit-legal";
    overlay.className = "legal-overlay";

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        overlay.classList.remove("show");
      }
    });

    document.body.appendChild(overlay);
  }

  overlay.innerHTML = `
    <article class="legal-dialog" role="dialog" aria-modal="true">
      <button
        class="legal-close"
        aria-label="Fechar"
        onclick="document.getElementById('lifefit-legal').classList.remove('show')"
      >×</button>
      ${legalText[type]}
    </article>
  `;

  overlay.classList.add("show");
};

async function authApi(path, options = {}) {
  const response = await fetch(`${LIFEFIT_AUTH_API}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data =
    response.status === 204
      ? null
      : await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error || "Não foi possível concluir esta ação. Tente novamente."
    );
  }

  return data;
}

function finishAuth(user) {
  usuarioLogadoEmail = user.email;
  usuarioLogadoNome = user.name;
  perfilAlimentarAtual = user.profile?.perfilAlimentar || null;
  favorites = new Set(user.profile?.favoritos || []);

  setLoggedInHeader(user.name);
  atualizarBadgeFavoritos();
  renderRecomendadas();
  renderRecipes(getAllRecipes());
}

function socialButton(provider, signup) {
  const icon = provider === "google" ? ICON_GOOGLE : ICON_FACEBOOK;
  const name = provider === "google" ? "Google" : "Facebook";

  return `
    <button
      type="button"
      onclick="startSocialLogin('${provider}', ${signup})"
    >
      ${icon} Continuar com ${name}
    </button>
  `;
}

window.startSocialLogin = function (provider, signup) {
  if (signup && !document.getElementById("signupTerms")?.checked) {
    showToast(
      "Você precisa aceitar os Termos de Uso e a Política de Privacidade."
    );
    return;
  }

  window.location.assign(
    `${LIFEFIT_AUTH_API}/${provider}?signup=${signup ? "1" : "0"}&termsAccepted=${signup ? "1" : "0"}`
  );
};

window.renderSignupForm = function () {
  const wrap = document.getElementById("authFormWrap");

  wrap.innerHTML = `
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="switchAuthTab('signup')">Criar conta</button>
      <button class="auth-tab" onclick="switchAuthTab('login')">Entrar</button>
    </div>

    <h2>Crie sua conta</h2>
    <p class="auth-sub">Salve suas receitas e seu planejamento alimentar.</p>

    <form onsubmit="handleSignup(event)">
      <div class="auth-field">
        <label for="signupName">Nome completo</label>
        <input type="text" id="signupName" required maxlength="120">
      </div>

      <div class="auth-field">
        <label for="signupEmail">E-mail</label>
        <input type="email" id="signupEmail" required>
      </div>

      <div class="auth-field">
        <label for="signupPass">Senha</label>
        <input type="password" id="signupPass" minlength="8" required>
      </div>

      <div class="auth-field">
        <label for="signupPassConfirm">Confirmar senha</label>
        <input type="password" id="signupPassConfirm" minlength="8" required>
      </div>

      <div class="auth-terms">
        <input type="checkbox" id="signupTerms" required>
        <label for="signupTerms">
          Concordo com os
          <a href="javascript:openLegal('terms')">Termos de Uso</a>
          e a
          <a href="javascript:openLegal('privacy')">Política de Privacidade</a>
          do LifeFIT.
        </label>
      </div>

      <button class="auth-submit" type="submit">Criar minha conta</button>
    </form>

    <div class="auth-divider">ou continue com</div>

    <div class="auth-social">
      ${socialButton("google", true)}
      ${socialButton("facebook", true)}
    </div>

    <p class="auth-switch">
      Já tem uma conta?
      <button onclick="switchAuthTab('login')">Entrar</button>
    </p>
  `;
};

window.renderLoginForm = function () {
  const wrap = document.getElementById("authFormWrap");

  wrap.innerHTML = `
    <div class="auth-tabs">
      <button class="auth-tab" onclick="switchAuthTab('signup')">Criar conta</button>
      <button class="auth-tab active" onclick="switchAuthTab('login')">Entrar</button>
    </div>

    <h2>Bem-vindo de volta</h2>
    <p class="auth-sub">Entre para acessar sua conta.</p>

    <form onsubmit="handleLogin(event)">
      <div class="auth-field">
        <label for="loginEmail">E-mail</label>
        <input type="email" id="loginEmail" required>
      </div>

      <div class="auth-field">
        <label for="loginPass">Senha</label>
        <input type="password" id="loginPass" required>
      </div>

      <button class="auth-submit" type="submit">Entrar</button>
    </form>

    <div class="auth-divider">ou continue com</div>

    <div class="auth-social">
      ${socialButton("google", false)}
      ${socialButton("facebook", false)}
    </div>

    <p class="auth-switch">
      Ainda não tem conta?
      <button onclick="switchAuthTab('signup')">Criar conta grátis</button>
    </p>
  `;
};

window.handleSignup = async function (event) {
  event.preventDefault();

  const password = signupPass.value;

  if (password !== signupPassConfirm.value) {
    showToast("As senhas não coincidem.");
    return;
  }

  if (!signupTerms.checked) {
    showToast(
      "Você precisa aceitar os Termos de Uso e a Política de Privacidade."
    );
    return;
  }

  try {
    const { user } = await authApi("/register", {
      method: "POST",
      body: JSON.stringify({
        name: signupName.value.trim(),
        email: signupEmail.value.trim(),
        password,
        termsAccepted: true
      })
    });

    finishAuth(user);
    closeAuth();
    showToast("Conta criada com sucesso.");
  } catch (error) {
    showToast(error.message);
  }
};

window.handleLogin = async function (event) {
  event.preventDefault();

  try {
    const { user } = await authApi("/login", {
      method: "POST",
      body: JSON.stringify({
        email: loginEmail.value.trim(),
        password: loginPass.value
      })
    });

    finishAuth(user);
    closeAuth();
    showToast("Login realizado!");
  } catch (error) {
    showToast(error.message);
  }
};

window.handleLogout = async function () {
  try {
    await authApi("/logout", {
      method: "POST"
    });
  } catch (_) {}

  usuarioLogadoEmail = null;
  usuarioLogadoNome = null;
  perfilAlimentarAtual = null;
  favorites = new Set();

  document.getElementById("headerAuthArea").innerHTML = `
    <button
      class="btn-header"
      id="btnCriarConta"
      onclick="openAuth('signup')"
    >
      <span class="full-label">Criar conta grátis</span>
      <span class="short-label">Entrar</span>
    </button>
  `;

  renderRecomendadas();
  renderRecipes(getAllRecipes());
};

function handleOAuthResult() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get("auth_error");
  const provider = params.get("provider");

  if (error) {
    const messages = {
      TERMS_REQUIRED:
        "Você precisa aceitar os Termos de Uso e a Política de Privacidade.",
      ACCOUNT_LINK_REQUIRED:
        "Este e-mail já possui uma conta no LifeFIT. Entre com e-mail e senha antes de vincular o login social.",
      access_denied:
        `Você cancelou o login com ${provider === "facebook" ? "Facebook" : "Google"}.`
    };

    showToast(
      messages[error] ||
        `Não foi possível entrar com ${provider === "facebook" ? "Facebook" : "Google"}. Tente novamente.`
    );

    window.history.replaceState({}, "", window.location.pathname);
    return;
  }

  if (params.get("auth_success")) {
    authApi("/me")
      .then(({ user }) => {
        finishAuth(user);
        showToast("Login realizado!");
      })
      .catch(() => {
        showToast("Não foi possível concluir o login. Tente novamente.");
      })
      .finally(() => {
        window.history.replaceState({}, "", window.location.pathname);
      });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  installLegalStyle();
  handleOAuthResult();

  authApi("/me")
    .then(({ user }) => finishAuth(user))
    .catch(() => {});
});