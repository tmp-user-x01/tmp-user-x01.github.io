/**
 * TOTP Engine - Handles the RFC 6238 logic
 * High cohesion: Focused solely on mathematical calculations and OTP generation.
 */
const TOTPEngine = (() => {
    /**
     * Decodes a Base32 string into a Uint8Array.
     * Includes padding handling and character validation.
     */
    const decodeBase32 = (base32) => {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleaned = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
        
        let bits = 0;
        let value = 0;
        let index = 0;
        const output = new Uint8Array(Math.floor((cleaned.length * 5) / 8));

        for (let i = 0; i < cleaned.length; i++) {
            const char = cleaned[i];
            const val = alphabet.indexOf(char);
            if (val === -1) throw new Error('Invalid Base32 character');

            value = (value << 5) | val;
            bits += 5;

            if (bits >= 8) {
                output[index++] = (value >>> (bits - 8)) & 255;
                bits -= 8;
            }
        }
        return output;
    };

    /**
     * Generates a TOTP code based on current timestamp and configuration.
     */
    const generateTOTP = (secret, digits = 6, period = 30, algorithm = 'SHA-1') => {
        try {
            const decodedSecret = decodeBase32(secret);
            const epoch = Math.floor(Date.now() / 1000);
            const timeStep = Math.floor(epoch / period);
            
            // Convert timeStep to 8-byte buffer (Big Endian)
            const timeBuffer = new ArrayBuffer(8);
            const view = new DataView(timeBuffer);
            view.setUint32(4, timeStep); // Setting lower 32 bits, upper bits remain 0

            // HMAC calculation using jsSHA
            const shaObj = new jsSHA(algorithm, "UINT8ARRAY");
            shaObj.setHMACKey(decodedSecret, "UINT8ARRAY");
            shaObj.update(new Uint8Array(timeBuffer));
            const hmac = shaObj.getHMAC("UINT8ARRAY");

            // Dynamic Truncation (RFC 4226)
            const offset = hmac[hmac.length - 1] & 0x0f;
            const binary =
                ((hmac[offset] & 0x7f) << 24) |
                ((hmac[offset + 1] & 0xff) << 16) |
                ((hmac[offset + 2] & 0xff) << 8) |
                (hmac[offset + 3] & 0xff);

            let otp = binary % Math.pow(10, digits);
            return otp.toString().padStart(digits, '0');
        } catch (e) {
            console.error('TOTP Generation Failed:', e);
            return null;
        }
    };

    return { generateTOTP, decodeBase32 };
})();

/**
 * State Manager - Tracks the current state of the application.
 * Separation of Concerns: Decoupled from UI rendering logic.
 */
const StateManager = {
    config: {
        secret: 'HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT',
        digits: 6,
        period: 30,
        algorithm: 'SHA-1'
    },
    currentCode: '000 000',
    timeLeft: 30,
    
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
    },

    sync() {
        const epoch = Math.floor(Date.now() / 1000);
        this.timeLeft = this.config.period - (epoch % this.config.period);
        this.currentCode = TOTPEngine.generateTOTP(
            this.config.secret,
            this.config.digits,
            this.config.period,
            this.config.algorithm
        );
    }
};

/**
 * UI Renderer - Manages visual updates and interaction effects.
 */
const UIRenderer = {
    elements: {
        code: document.getElementById('totp-code'),
        timer: document.getElementById('expiration-time'),
        progressBar: document.getElementById('progress-bar'),
        qrcodeBox: document.getElementById('qrcode'),
        copyBtn: document.getElementById('copy-btn'),
        secretInput: document.getElementById('secret-input')
    },

    qrInstance: null,

    init() {
        this.qrInstance = new QRCode(this.elements.qrcodeBox, {
            width: 200,
            height: 200,
            correctLevel: QRCode.CorrectLevel.M
        });
    },

    update(state) {
        const { currentCode, timeLeft, config } = state;
        
        // Update Code Display
        if (currentCode) {
            // Format 123456 -> 123 456
            const formattedCode = currentCode.length === 6 
                ? `${currentCode.slice(0, 3)} ${currentCode.slice(3)}`
                : currentCode;
            this.elements.code.innerText = formattedCode;
            this.elements.code.style.opacity = "1";
        } else {
            this.elements.code.innerText = "INVALID";
            this.elements.code.style.opacity = "0.5";
        }

        // Update Timer Text
        this.elements.timer.innerText = timeLeft;

        // Update Progress Bar
        const progress = (timeLeft / config.period) * 100;
        this.elements.progressBar.style.width = `${progress}%`;
        this.elements.progressBar.classList.toggle('warning', timeLeft <= 5);

        // Update QR Code
        const label = "TOTP-Generator";
        const issuer = "Antigravity";
        const otpauth = `otpauth://totp/${issuer}:${label}?secret=${config.secret}&issuer=${issuer}&digits=${config.digits}&period=${config.period}&algorithm=${config.algorithm}`;
        this.qrInstance.makeCode(otpauth);
    },

    showCopySuccess() {
        const btn = this.elements.copyBtn;
        const originalText = btn.querySelector('span').innerText;
        btn.classList.add('success');
        btn.querySelector('span').innerText = 'Copied!';
        
        setTimeout(() => {
            btn.classList.remove('success');
            btn.querySelector('span').innerText = originalText;
        }, 2000);
    }
};

/**
 * App Controller - Orchestrates the flow and events.
 * The glue between State and UI.
 */
const AppController = {
    init() {
        UIRenderer.init();
        this.bindEvents();
        this.startHeartbeat();
        this.syncAll();
    },

    bindEvents() {
        const inputs = {
            secret: document.getElementById('secret-input'),
            digits: document.getElementById('digits-select'),
            period: document.getElementById('period-input'),
            algorithm: document.getElementById('algorithm-select')
        };

        // Listen for all input changes
        Object.keys(inputs).forEach(key => {
            inputs[key].addEventListener('input', () => {
                StateManager.updateConfig({
                    [key]: inputs[key].value
                });
                this.syncAll();
            });
        });

        // Copy Button Event
        document.getElementById('copy-btn').addEventListener('click', () => {
            if (StateManager.currentCode) {
                navigator.clipboard.writeText(StateManager.currentCode);
                UIRenderer.showCopySuccess();
            }
        });
    },

    startHeartbeat() {
        setInterval(() => {
            StateManager.sync();
            UIRenderer.update(StateManager);
        }, 1000);
    },

    syncAll() {
        StateManager.sync();
        UIRenderer.update(StateManager);
    }
};

// Application Boot
document.addEventListener('DOMContentLoaded', () => AppController.init());
