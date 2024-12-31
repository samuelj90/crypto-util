#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const { program } = require('commander');

// Helper function to read the public or private key from a file
function readKeyFromFile(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        console.error(`Error reading key file at ${filePath}:`, err.message);
        process.exit(1);
    }
}

// Helper function to decode base64-encoded key
function decodeBase64Key(base64Key) {
    try {
        return Buffer.from(base64Key, 'base64').toString('utf8');
    } catch (err) {
        console.error('Error decoding base64 key:', err.message);
        process.exit(1);
    }
}

// AES Encryption function (AES-256-CBC)
function encryptAES(plaintext, password) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);  // 16-byte initialization vector
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256'); // Derive 32-byte key from password

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return { salt: salt.toString('base64'), iv: iv.toString('base64'), ciphertext: encrypted };
}

// AES Decryption function (AES-256-CBC)
function decryptAES(encryptedData, password) {
    const { salt, iv, ciphertext } = encryptedData;
    const saltBuffer = Buffer.from(salt, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');
    const key = crypto.pbkdf2Sync(password, saltBuffer, 100000, 32, 'sha256');

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// RSA Encryption (asymmetric encryption)
function encryptRSA(plaintext, publicKey) {
    const buffer = Buffer.from(plaintext, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

// RSA Decryption (asymmetric encryption)
function decryptRSA(encryptedData, privateKey) {
    const buffer = Buffer.from(encryptedData, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf8');
}

// Hashing function (SHA-256, SHA-512, etc.)
function hash(input, algorithm = 'sha256') {
    const hash = crypto.createHash(algorithm);
    hash.update(input);
    return hash.digest('hex');
}

// Command-line interface logic using commander.js
program
    .name('crypto-cli')
    .description('A simple command-line utility for encryption, decryption, and hashing with multiple algorithms.')
    .version('1.0.0');

// Encrypt command
program
    .command('encrypt')
    .description('Encrypt a message using selected algorithm')
    .requiredOption('-p, --password <password>', 'Password for encryption (used in symmetric algorithms like AES)')
    .requiredOption('-m, --message <message>', 'Plaintext message to encrypt')
    .option('-a, --algorithm <algorithm>', 'Encryption algorithm (aes, rsa)', 'aes') // Default to AES
    .option('-k, --key <key>', 'Public or private key for RSA (passed as base64 or file path)', '')
    .action((options) => {
        let encryptedData;

        if (options.algorithm === 'aes') {
            encryptedData = encryptAES(options.message, options.password);
        } else if (options.algorithm === 'rsa') {
            if (!options.key) {
                console.error('RSA key is required for RSA encryption!');
                process.exit(1);
            }

            let publicKey;
            if (fs.existsSync(options.key)) {
                // If the key is a file path, read the key from the file
                publicKey = readKeyFromFile(options.key);
            } else {
                // If the key is a base64 encoded string
                publicKey = decodeBase64Key(options.key);
            }
            encryptedData = encryptRSA(options.message, publicKey);
        } else {
            console.error('Unsupported encryption algorithm!');
            process.exit(1);
        }

        console.log('Encrypted Data:', JSON.stringify(encryptedData, null, 2));
    });

// Decrypt command
program
    .command('decrypt')
    .description('Decrypt a message using selected algorithm')
    .requiredOption('-p, --password <password>', 'Password for decryption (used in symmetric algorithms like AES)')
    .requiredOption('-d, --data <data>', 'Encrypted data (in JSON format for AES, base64 for RSA)')
    .option('-a, --algorithm <algorithm>', 'Decryption algorithm (aes, rsa)', 'aes') // Default to AES
    .option('-k, --key <key>', 'Private key for RSA (passed as base64 or file path)', '')
    .action((options) => {
        let decryptedMessage;

        try {
            const encryptedData = JSON.parse(options.data);

            if (options.algorithm === 'aes') {
                decryptedMessage = decryptAES(encryptedData, options.password);
            } else if (options.algorithm === 'rsa') {
                if (!options.key) {
                    console.error('RSA private key is required for RSA decryption!');
                    process.exit(1);
                }

                let privateKey;
                if (fs.existsSync(options.key)) {
                    privateKey = readKeyFromFile(options.key);
                } else {
                    privateKey = decodeBase64Key(options.key);
                }

                decryptedMessage = decryptRSA(options.data, privateKey);
            } else {
                console.error('Unsupported decryption algorithm!');
                process.exit(1);
            }
        } catch (error) {
            console.error('Error parsing encrypted data:', error.message);
            process.exit(1);
        }

        console.log('Decrypted Message:', decryptedMessage);
    });

// Hashing command
program
    .command('hash')
    .description('Generate a hash using selected algorithm')
    .requiredOption('-s, --string <string>', 'String to hash')
    .option('-a, --algorithm <algorithm>', 'Hashing algorithm (sha256, sha512)', 'sha256') // Default to SHA-256
    .action((options) => {
        const hashedString = hash(options.string, options.algorithm);
        console.log(`${options.algorithm.toUpperCase()} Hash:`, hashedString);
    });

// Parse the command-line arguments
program.parse(process.argv);
