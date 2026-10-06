/**
 * ==============================================================================
 * AUTH & SECURITY CORE ENGINE — PRÁCTICAS PROFESIONALES
 * Desarrollado por Kevin Lujan & Mauricio Prieto
 * 
 * Implementación de Controles de Seguridad OWASP Top 10:
 * - Anti-Brute Force con Bloqueo Progresivo y Delay Anti-Timing
 * - Simulación de JWT Criptográfico con Firma HMAC-SHA256 (Web Crypto API)
 * - Protección contra Clickjacking (Frame-Busting Shield)
 * - Sanitización estricta de Entradas (XSS & Injection Shield)
 * - Monitor de Inactividad de Sesión (Session Timeout)
 * - Verificación de Integridad de Tokens en LocalStorage
 * - Resolución Dinámica de Rutas Absolutas/Relativas Multi-Nivel
 * ==============================================================================
 */

(function (window) {
    'use strict';

    // 1. ESCUDO ANTI-CLICKJACKING (Previene embedding no autorizado en iframes)
    try {
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
    } catch (e) {
        console.warn('[Security Guard] Frame-busting warning:', e);
    }

    // Configuración de Seguridad
    const CONFIG = {
        TOKEN_KEY: 'auth_jwt_token',
        LEGACY_TOKEN_KEY: 'auth_token',
        USER_KEY: 'auth_user_data',
        LOCKOUT_KEY: 'auth_lockout_data',
        AUDIT_KEY: 'auth_security_audit',
        LAST_ACTIVITY_KEY: 'auth_last_activity',
        MAX_FAILED_ATTEMPTS: 5,
        LOCKOUT_TIME_SECONDS: 30, // 30s tras 5 intentos
        EXTENDED_LOCKOUT_SECONDS: 300, // 5 min tras 10 intentos
        SESSION_DURATION_MS: 2 * 60 * 60 * 1000, // 2 horas
        INACTIVITY_TIMEOUT_MS: 15 * 60 * 1000, // 15 minutos
        HMAC_SECRET: 'AGY-SECURE-KEY-2026-KEVIN-MAURICIO'
    };

    /**
     * Detector Dinámico de Rutas Relativas al Root
     * Permite que auth funcione desde raíz, 1 nivel o 3 niveles de profundidad
     */
    function getRootPath() {
        try {
            const rawPath = window.location.pathname.replace(/\\/g, '/');
            const path = decodeURIComponent(rawPath).toLowerCase();
            if (path.includes('/kevin_eduardo_lujan_prado_earth_theory') || path.includes('/earth_theory/') || path.includes('/earth theory/')) {
                return '../../../';
            }
            if (path.includes('/potato/')) {
                return '../../';
            }
            if (path.includes('/practicas/')) {
                return '../';
            }
        } catch (e) {
            console.error('[AuthGuard] Error calculating getRootPath:', e);
        }
        return './';
    }

    /**
     * Sanitizador estricto de entradas (Mitigación XSS & Script Injection)
     */
    function sanitize(str) {
        if (typeof str !== 'string') return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '`': '&#x60;'
        };
        const reg = /[&<>"'`/]/ig;
        return str.replace(reg, (match) => (map[match])).trim();
    }

    /**
     * Motor Criptográfico HMAC-SHA256 usando Web Crypto API
     */
    async function generateHMAC(message, secret) {
        try {
            const encoder = new TextEncoder();
            const keyData = encoder.encode(secret);
            const messageData = encoder.encode(message);

            const cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: { name: 'SHA-256' } },
                false,
                ['sign']
            );

            const signatureBuffer = await window.crypto.subtle.sign('HMAC', cryptoKey, messageData);
            const signatureArray = Array.from(new Uint8Array(signatureBuffer));
            return signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (err) {
            console.error('[Crypto Engine] Error calculando HMAC:', err);
            let hash = 0;
            for (let i = 0; i < message.length; i++) {
                hash = ((hash << 5) - hash) + message.charCodeAt(i);
                hash |= 0;
            }
            return 'fallback_' + Math.abs(hash).toString(16);
        }
    }

    /**
     * Registro de Auditoría de Seguridad
     */
    function logAuditEvent(type, details) {
        try {
            const logs = JSON.parse(localStorage.getItem(CONFIG.AUDIT_KEY) || '[]');
            logs.unshift({
                id: 'evt_' + Math.random().toString(36).substr(2, 9),
                timestamp: new Date().toISOString(),
                type: sanitize(type),
                details: sanitize(details),
                ipSimulated: '192.168.1.1'
            });
            if (logs.length > 20) logs.pop();
            localStorage.setItem(CONFIG.AUDIT_KEY, JSON.stringify(logs));
        } catch (e) {
            console.warn('[Audit Logger] Error guardando log:', e);
        }
    }

    /**
     * Verificación del Estado de Bloqueo Anti-Fuerza Bruta
     */
    function getLockoutStatus() {
        try {
            const data = JSON.parse(localStorage.getItem(CONFIG.LOCKOUT_KEY) || '{}');
            const now = Date.now();

            if (data.lockedUntil && now < data.lockedUntil) {
                const remainingSeconds = Math.ceil((data.lockedUntil - now) / 1000);
                return {
                    isLocked: true,
                    remainingSeconds: remainingSeconds,
                    attempts: data.attempts || 0,
                    attemptsLeft: 0
                };
            }

            if (data.lockedUntil && now >= data.lockedUntil) {
                return {
                    isLocked: false,
                    remainingSeconds: 0,
                    attempts: data.attempts || 0,
                    attemptsLeft: Math.max(0, CONFIG.MAX_FAILED_ATTEMPTS - (data.attempts || 0))
                };
            }

            const currentAttempts = data.attempts || 0;
            return {
                isLocked: false,
                remainingSeconds: 0,
                attempts: currentAttempts,
                attemptsLeft: Math.max(0, CONFIG.MAX_FAILED_ATTEMPTS - currentAttempts)
            };
        } catch (e) {
            return { isLocked: false, remainingSeconds: 0, attempts: 0, attemptsLeft: CONFIG.MAX_FAILED_ATTEMPTS };
        }
    }

    /**
     * Registrar Intento Fallido de Login
     */
    function recordFailedAttempt() {
        try {
            const data = JSON.parse(localStorage.getItem(CONFIG.LOCKOUT_KEY) || '{}');
            const attempts = (data.attempts || 0) + 1;
            let lockedUntil = null;

            if (attempts >= 10) {
                lockedUntil = Date.now() + (CONFIG.EXTENDED_LOCKOUT_SECONDS * 1000);
                logAuditEvent('BRUTE_FORCE_LOCKOUT_EXTENDED', `Bloqueo extendido de 5 min activado tras ${attempts} intentos fallidos.`);
            } else if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                lockedUntil = Date.now() + (CONFIG.LOCKOUT_TIME_SECONDS * 1000);
                logAuditEvent('BRUTE_FORCE_LOCKOUT', `Bloqueo preventivo de 30s activado tras ${attempts} intentos fallidos.`);
            } else {
                logAuditEvent('FAILED_LOGIN_ATTEMPT', `Intento fallido ${attempts} de ${CONFIG.MAX_FAILED_ATTEMPTS}`);
            }

            localStorage.setItem(CONFIG.LOCKOUT_KEY, JSON.stringify({
                attempts: attempts,
                lockedUntil: lockedUntil,
                lastAttempt: Date.now()
            }));
        } catch (e) {
            console.error('[Security Engine] Error registrando intento fallido:', e);
        }
    }

    /**
     * Restablecer Contador de Intentos Fallidos
     */
    function resetLockout() {
        localStorage.removeItem(CONFIG.LOCKOUT_KEY);
    }

    /**
     * Generación de JWT Simulado Criptográfico con Header, Payload y Firma HMAC
     */
    async function createSecureToken(username, role = 'Administrator') {
        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };

        const now = Date.now();
        const payload = {
            sub: sanitize(username),
            user: sanitize(username),
            role: sanitize(role),
            iat: now,
            exp: now + CONFIG.SESSION_DURATION_MS,
            jti: 'tok_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now()
        };

        const encodedHeader = btoa(JSON.stringify(header));
        const encodedPayload = btoa(JSON.stringify(payload));
        const message = `${encodedHeader}.${encodedPayload}`;
        const signature = await generateHMAC(message, CONFIG.HMAC_SECRET);

        return `${message}.${signature}`;
    }

    /**
     * Verificación y Validación Estricta del Token JWT (Almacenado en sessionStorage para expirar al cerrar pestaña)
     */
    async function verifyToken(token) {
        if (!token) {
            token = sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY);
        }
        if (!token || typeof token !== 'string') return { valid: false, reason: 'Token inexistente' };

        // Si es un token de 3 partes con firma HMAC
        const parts = token.split('.');
        if (parts.length === 3) {
            const [encodedHeader, encodedPayload, signature] = parts;
            const message = `${encodedHeader}.${encodedPayload}`;

            // 1. Verificar Firma HMAC
            const expectedSignature = await generateHMAC(message, CONFIG.HMAC_SECRET);
            if (signature !== expectedSignature) {
                logAuditEvent('TOKEN_TAMPERING_DETECTED', 'Alerta: Token con firma HMAC alterada.');
                return { valid: false, reason: 'Firma HMAC inválida: Posible intento de manipulación' };
            }

            // 2. Decodificar Payload
            let payload;
            try {
                payload = JSON.parse(atob(encodedPayload));
            } catch (e) {
                return { valid: false, reason: 'Error al decodificar carga útil de JWT' };
            }

            // 3. Expiración
            const now = Date.now();
            if (now > payload.exp) {
                logAuditEvent('SESSION_EXPIRED', `El token para ${payload.user} ha expirado.`);
                return { valid: false, reason: 'El token ha expirado. Sesión finalizada.' };
            }

            // 4. Inactividad
            const lastActivity = parseInt(sessionStorage.getItem(CONFIG.LAST_ACTIVITY_KEY) || '0', 10);
            if (lastActivity && (now - lastActivity > CONFIG.INACTIVITY_TIMEOUT_MS)) {
                logAuditEvent('INACTIVITY_TIMEOUT', `Sesión cerrada por inactividad (> 15 min).`);
                return { valid: false, reason: 'Sesión cerrada por inactividad de más de 15 minutos.' };
            }

            sessionStorage.setItem(CONFIG.LAST_ACTIVITY_KEY, now.toString());
            return { valid: true, payload: payload };
        } else {
            // Soporte token legacy btoa({ user, exp })
            try {
                const payload = JSON.parse(atob(token));
                if (Date.now() > payload.exp) {
                    return { valid: false, reason: 'Token expirado' };
                }
                return { valid: true, payload: payload };
            } catch (e) {
                return { valid: false, reason: 'Formato de token desconocido' };
            }
        }
    }

    /**
     * Iniciar Sesión con Protección Completa (Almacenamiento en sessionStorage)
     */
    async function login(username, password) {
        const lockout = getLockoutStatus();
        if (lockout.isLocked) {
            return {
                success: false,
                message: `Demasiados intentos fallidos. Sistema bloqueado por ${lockout.remainingSeconds} segundos.`,
                remainingSeconds: lockout.remainingSeconds
            };
        }

        // Límite de longitud de entrada para prevenir ataques de desbordamiento
        const cleanUser = sanitize((username || '').trim().substring(0, 64));
        const cleanPass = (password || '').trim().substring(0, 64);

        // Anti-Timing Attack Delay
        await new Promise(r => setTimeout(r, 320));

        // Validación de credenciales autorizadas
        const isMike = cleanUser.toLowerCase() === 'mike' && 
            (cleanPass === 'Mike' || cleanPass === 'mike' || cleanPass === 'Mike2026' || cleanPass === '1234');
        const isAdmin = cleanUser.toLowerCase() === 'admin' && cleanPass === '1234';
        const isKevin = cleanUser.toLowerCase() === 'kevin' && cleanPass === 'kevin2026';
        const isMauricio = cleanUser.toLowerCase() === 'mauricio' && cleanPass === 'mauricio2026';

        const validCredentials = isMike || isAdmin || isKevin || isMauricio;

        if (validCredentials) {
            resetLockout();
            
            const role = isMike ? 'Evaluador Oficial' : (isAdmin ? 'Super Administrador' : 'Investigador Principal');
            const displayName = isMike ? 'Mike' : (isAdmin ? 'Kevin Lujan & Mauricio Prieto' : cleanUser.charAt(0).toUpperCase() + cleanUser.slice(1));
            
            const token = await createSecureToken(cleanUser, role);

            // Almacenar en sessionStorage: Se destruye automáticamente al cerrar la pestaña/ventana
            sessionStorage.setItem(CONFIG.TOKEN_KEY, token);
            sessionStorage.setItem(CONFIG.LEGACY_TOKEN_KEY, token);
            sessionStorage.setItem(CONFIG.USER_KEY, JSON.stringify({
                username: cleanUser,
                displayName: displayName,
                role: role,
                loginTime: new Date().toLocaleTimeString(),
                sessionExpiry: Date.now() + CONFIG.SESSION_DURATION_MS
            }));
            sessionStorage.setItem(CONFIG.LAST_ACTIVITY_KEY, Date.now().toString());

            // Limpiar cualquier token persistente anterior en localStorage
            localStorage.removeItem(CONFIG.TOKEN_KEY);
            localStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);
            localStorage.removeItem(CONFIG.USER_KEY);

            logAuditEvent('LOGIN_SUCCESS', `Inicio de sesión exitoso para: ${cleanUser} con rol ${role}`);

            return {
                success: true,
                message: 'Autenticación exitosa. Redirigiendo...',
                user: cleanUser
            };
        } else {
            recordFailedAttempt();
            const newLockout = getLockoutStatus();
            return {
                success: false,
                message: newLockout.isLocked
                    ? `Bloqueo de seguridad activado por ${newLockout.remainingSeconds} segundos.`
                    : `Credenciales incorrectas. Te quedan ${newLockout.attemptsLeft} intentos antes del bloqueo.`,
                attemptsLeft: newLockout.attemptsLeft,
                remainingSeconds: newLockout.remainingSeconds
            };
        }
    }

    /**
     * Cerrar Sesión de Forma Segura
     */
    function logout(reason) {
        logAuditEvent('LOGOUT', reason || 'Cierre de sesión manual voluntario.');
        
        sessionStorage.removeItem(CONFIG.TOKEN_KEY);
        sessionStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);
        sessionStorage.removeItem(CONFIG.USER_KEY);
        sessionStorage.removeItem(CONFIG.LAST_ACTIVITY_KEY);

        localStorage.removeItem(CONFIG.TOKEN_KEY);
        localStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);
        localStorage.removeItem(CONFIG.USER_KEY);

        const root = getRootPath();
        window.location.href = root + 'login.html' + (reason ? `?reason=${encodeURIComponent(reason)}` : '');
    }

    /**
     * Proteger Ruta
     */
    async function protectRoute() {
        const token = sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY);
        const check = await verifyToken(token);

        if (!check.valid) {
            console.warn('[Security Guard] Acceso no autorizado o sesión cerrada:', check.reason);
            sessionStorage.removeItem(CONFIG.TOKEN_KEY);
            sessionStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);
            sessionStorage.removeItem(CONFIG.USER_KEY);
            localStorage.removeItem(CONFIG.TOKEN_KEY);
            localStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);
            localStorage.removeItem(CONFIG.USER_KEY);
            
            const root = getRootPath();
            window.location.href = root + 'login.html?security_alert=' + encodeURIComponent(check.reason);
            return false;
        }

        return true;
    }

    /**
     * Redirigir si ya está autenticado
     */
    async function redirectIfAuthenticated() {
        const token = sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY);
        if (!token) return;

        const check = await verifyToken(token);
        if (check.valid) {
            const root = getRootPath();
            window.location.href = root + 'dashboard.html';
        }
    }

    function isAuthenticated() {
        const token = sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY);
        return !!token;
    }

    function getCurrentUser() {
        try {
            return JSON.parse(sessionStorage.getItem(CONFIG.USER_KEY) || 'null');
        } catch (e) {
            return null;
        }
    }

    function getAuditLogs() {
        try {
            return JSON.parse(localStorage.getItem(CONFIG.AUDIT_KEY) || '[]');
        } catch (e) {
            return [];
        }
    }

    function setupActivityWatcher() {
        const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
        let throttleTimer = null;

        const updateActivity = () => {
            if (!throttleTimer) {
                throttleTimer = setTimeout(() => {
                    if (sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY)) {
                        sessionStorage.setItem(CONFIG.LAST_ACTIVITY_KEY, Date.now().toString());
                    }
                    throttleTimer = null;
                }, 3000);
            }
        };

        events.forEach(evt => window.addEventListener(evt, updateActivity, { passive: true }));

        setInterval(async () => {
            const token = sessionStorage.getItem(CONFIG.TOKEN_KEY) || sessionStorage.getItem(CONFIG.LEGACY_TOKEN_KEY);
            if (token) {
                const check = await verifyToken(token);
                if (!check.valid) {
                    logout(check.reason);
                }
            }
        }, 30000);
    }

    if (typeof window !== 'undefined') {
        setupActivityWatcher();
    }

    window.Auth = {
        login,
        logout,
        protectRoute,
        redirectIfAuthenticated,
        isAuthenticated,
        getCurrentUser,
        getLockoutStatus,
        getAuditLogs,
        sanitize,
        getRootPath,
        verifyToken
    };

    window.protectRoute = protectRoute;
    window.redirectIfAuthenticated = redirectIfAuthenticated;
    window.isAuthenticated = isAuthenticated;
    window.logout = logout;

})(typeof window !== 'undefined' ? window : this);