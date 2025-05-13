document.addEventListener('DOMContentLoaded', () => {
    const encryptBtn = document.getElementById('encrypt-btn');
    const decryptBtn = document.getElementById('decrypt-btn');
    const copyEncryptedBtn = document.getElementById('copy-encrypted-btn');

    const encryptMessageInput = document.getElementById('encrypt-message');
    const encryptPasswordInput = document.getElementById('encrypt-password');
    const encryptedOutput = document.getElementById('encrypted-output');

    const decryptMessageInput = document.getElementById('decrypt-message');
    const decryptPasswordInput = document.getElementById('decrypt-password');
    const decryptedOutput = document.getElementById('decrypted-output');

    const statusMessage = document.getElementById('status-message');

    const SALT_LENGTH = 16; // bytes
    const IV_LENGTH = 12;   // bytes for AES-GCM
    const PBKDF2_ITERATIONS = 100000; // Number of iterations for PBKDF2

    // --- Helper Functions ---
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function showStatus(message, isError = false) {
        statusMessage.textContent = message;
        statusMessage.className = 'status ' + (isError ? 'error' : 'success');
        setTimeout(() => { statusMessage.textContent = ''; statusMessage.className = 'status'; }, 5000);
    }

    // --- Crypto Core Functions ---

    async function getKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptData(text, password) {
        if (!text || !password) {
            showStatus("Message and password are required for encryption.", true);
            return null;
        }
        try {
            const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            const key = await getKey(password, salt);

            const enc = new TextEncoder();
            const encodedText = enc.encode(text);

            const ciphertext = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                encodedText
            );

            // Prepend salt and IV to the ciphertext for storage/transmission
            // Format: salt (16 bytes) + iv (12 bytes) + ciphertext
            const resultBuffer = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
            resultBuffer.set(salt, 0);
            resultBuffer.set(iv, salt.length);
            resultBuffer.set(new Uint8Array(ciphertext), salt.length + iv.length);

            return arrayBufferToBase64(resultBuffer.buffer);

        } catch (e) {
            console.error("Encryption error:", e);
            showStatus(`Encryption failed: ${e.message}`, true);
            return null;
        }
    }

    async function decryptData(base64Ciphertext, password) {
        if (!base64Ciphertext || !password) {
            showStatus("Ciphertext and password are required for decryption.", true);
            return null;
        }
        try {
            const encryptedDataBuffer = base64ToArrayBuffer(base64Ciphertext);

            // Extract salt, IV, and actual ciphertext
            const salt = encryptedDataBuffer.slice(0, SALT_LENGTH);
            const iv = encryptedDataBuffer.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
            const ciphertext = encryptedDataBuffer.slice(SALT_LENGTH + IV_LENGTH);

            const key = await getKey(password, salt);

            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                ciphertext
            );

            const dec = new TextDecoder();
            return dec.decode(decryptedBuffer);

        } catch (e) {
            console.error("Decryption error:", e);
            // Common error: "CipherNormalOperation" often means wrong password or corrupted data
            if (e.name === "OperationError" && (e.message.includes("CipherFinal") || e.message.includes("Cipher"))) {
                 showStatus("Decryption failed. Incorrect password or corrupted data.", true);
            } else {
                 showStatus(`Decryption failed: ${e.message}`, true);
            }
            return null;
        }
    }


    // --- Event Listeners ---
    encryptBtn.addEventListener('click', async () => {
        const message = encryptMessageInput.value;
        const password = encryptPasswordInput.value;
        encryptedOutput.value = ''; // Clear previous output

        const encrypted = await encryptData(message, password);
        if (encrypted) {
            encryptedOutput.value = encrypted;
            showStatus("Message encrypted successfully!", false);
        }
    });

    decryptBtn.addEventListener('click', async () => {
        const ciphertext = decryptMessageInput.value;
        const password = decryptPasswordInput.value;
        decryptedOutput.value = ''; // Clear previous output

        const decrypted = await decryptData(ciphertext, password);
        if (decrypted !== null) { // Check for null explicitly as empty string is a valid decryption
            decryptedOutput.value = decrypted;
            showStatus("Message decrypted successfully!", false);
        }
    });

    copyEncryptedBtn.addEventListener('click', () => {
        if (encryptedOutput.value) {
            encryptedOutput.select();
            document.execCommand('copy'); // Deprecated but widely supported for simple copy
            // For modern approach: navigator.clipboard.writeText(encryptedOutput.value)
            // .then(() => showStatus("Ciphertext copied to clipboard!", false))
            // .catch(err => showStatus("Failed to copy ciphertext.", true));
            showStatus("Ciphertext copied to clipboard!", false);
        } else {
            showStatus("Nothing to copy.", true);
        }
    });

});
