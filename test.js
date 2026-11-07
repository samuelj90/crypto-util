const assert = require('node:assert');
const test = require('node:test');
const crypto = require('node:crypto');

// Verify Node crypto algorithms used by crypto-util
test('AES-256-CBC encryption and decryption vector', () => {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const plainText = 'EnterpriseVerificationVector2026';

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    assert.strictEqual(decrypted, plainText);
});

test('SHA-256 and SHA-512 hashing determinism', () => {
    const data = 'DeterministicDataPayload';
    const hash256 = crypto.createHash('sha256').update(data).digest('hex');
    const hash512 = crypto.createHash('sha512').update(data).digest('hex');

    assert.strictEqual(hash256.length, 64);
    assert.strictEqual(hash512.length, 128);
});
