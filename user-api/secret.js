const crypto = require('crypto');

// Fonction pour générer une clé secrète aléatoire
function generateJwtSecret() {
    return crypto.randomBytes(32).toString('hex');
}

console.log(generateJwtSecret());
