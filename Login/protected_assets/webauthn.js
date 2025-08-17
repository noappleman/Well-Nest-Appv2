// Helper function to convert base64url to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));
}

// Helper function to get CSRF token
function getCSRFToken() {
    return document.querySelector('input[name="csrf_token"]').value;
}

// Helper function to convert ArrayBuffer to base64url
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

const handleLogin = () => {
    const usernameInput = document.getElementById('username');
    const webauthnLoginContainer = document.getElementById('webauthn-login-container');
    const webauthnLoginButton = document.getElementById('webauthn-login-button');

    // If these elements don't exist, we're not on the login page, so do nothing.
    if (!usernameInput || !webauthnLoginContainer || !webauthnLoginButton) {
        return;
    }

    usernameInput.addEventListener('input', async () => {
        const username = usernameInput.value;
        if (username.length > 2) {
            const resp = await fetch('/webauthn/login/check', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify({ username }),
            });
            const data = await resp.json();
            webauthnLoginContainer.style.display = data.is_registered ? 'block' : 'none';
        }
    });

    webauthnLoginButton.addEventListener('click', async () => {
        const username = usernameInput.value;
        try {
            const resp = await fetch('/webauthn/login/begin', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify({ username }),
            });
            let options = await resp.json();

            options.challenge = bufferDecode(options.challenge);
            for (let cred of options.allowCredentials) {
                cred.id = bufferDecode(cred.id);
            }

            const assertion = await navigator.credentials.get({ publicKey: options });

            const assertionResponse = {
                id: assertion.id,
                rawId: bufferEncode(assertion.rawId),
                response: {
                    authenticatorData: bufferEncode(assertion.response.authenticatorData),
                    clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                    signature: bufferEncode(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferEncode(assertion.response.userHandle) : null,
                },
                type: assertion.type,
            };

            const verificationResp = await fetch('/webauthn/login/complete', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify(assertionResponse),
            });

            const verificationJSON = await verificationResp.json();
            if (verificationJSON && verificationJSON.verified) {
                // Force redirect to homepage with timestamp to prevent caching
                const timestamp = new Date().getTime();
                window.location.href = '/homepage?t=' + timestamp;
                // Fallback redirect after a short delay if the above doesn't work
                setTimeout(() => {
                    window.location.replace('/homepage');
                }, 500);
            } else {
                alert('Failed to login with Touch ID: ' + verificationJSON.error);
            }
        } catch (err) {
            console.error(err);
            alert('Could not login with Touch ID: ' + err);
        }
    });
};

const handleRegistration = () => {
    const registerButton = document.getElementById('register-webauthn');
    if (!registerButton) return;

    registerButton.addEventListener('click', async () => {
        try {
            const resp = await fetch('/webauthn/register/begin', { 
                method: 'POST',
                headers: { 'X-CSRFToken': getCSRFToken() }
            });
            let options = await resp.json();

            options.challenge = bufferDecode(options.challenge);
            options.user.id = bufferDecode(options.user.id);
            if (options.excludeCredentials) {
                for (let cred of options.excludeCredentials) {
                    cred.id = bufferDecode(cred.id);
                }
            }

            const cred = await navigator.credentials.create({ publicKey: options });

            const attestationResponse = {
                id: cred.id,
                rawId: bufferEncode(cred.rawId),
                response: {
                    clientDataJSON: bufferEncode(cred.response.clientDataJSON),
                    attestationObject: bufferEncode(cred.response.attestationObject),
                },
                type: cred.type,
            };

            const verificationResp = await fetch('/webauthn/register/complete', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify(attestationResponse),
            });

            const verificationJSON = await verificationResp.json();
            if (verificationJSON && verificationJSON.verified) {
                alert('Authenticator registered successfully!');
                window.location.reload();
            } else {
                alert('Failed to register authenticator: ' + verificationJSON.error);
            }
        } catch (err) {
            console.error('WebAuthn registration error:', err);
            console.error('Error details:', err.message, err.name);
            const errorMsg = 'Could not register authenticator: ' + err.message + ' (Check console for details)';
            alert(errorMsg);
            // Also log to console so we can see it
            setTimeout(() => {
                console.log('Alert should have shown:', errorMsg);
            }, 100);
        }
    });
};

document.addEventListener('DOMContentLoaded', () => {
    handleLogin();
    handleRegistration();
});
