// In utilities.js
function generateMfaCode() {
    const codeLength = 6;
    let code = '';
    for (let i = 0; i < codeLength; i++) {
        code += Math.floor(Math.random() * 10); // Generates a random digit (0-9)
    }
    return code;
}

function sendMfaCode(phoneNumber, mfaCode) {
    // In a real application, integrate with an SMS gateway or email service
    // For demo purposes, we're just logging to the console
    console.log(`Sending MFA code ${mfaCode} to ${phoneNumber}`);
}

module.exports = {
    generateMfaCode,
    sendMfaCode
};


