function decryptMessages(privateKeyPem) {
    // Import the private key using Forge
    fetch('https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js')
    .then(response => response.text())
    .then(scriptContent => {
        // Load forge library, was recommended to use this from chatgpt and online
        const script = document.createElement('script');
        script.text = scriptContent;
        document.head.appendChild(script);

        // decrypt with private key
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const encryptedMessages = document.querySelectorAll('.encrypted-message');

        if (!encryptedMessages || encryptedMessages.length === 0) {
            console.log('No messages to decrypt.');
            return;
        }

        // Clear the messages list before appending decrypted messages
        encryptedMessages.forEach((element, index) => {
            try {
                // Get the encrypted message from the data attribute
                const encryptedMessageHex = element.getAttribute('data-message');
                const encryptedBytes = forge.util.hexToBytes(encryptedMessageHex);

                // decrypt the message using RSA
                const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP');

                // Display the decrypted message in the DOM
                element.textContent = decrypted;
            } catch (error) {
                console.error('Decryption failed for message:', error);
                element.textContent = '[Decryption Failed]';
            }
        });
    })
    .catch(error => {
        console.error('Error loading Forge library:', error);
    });
}
