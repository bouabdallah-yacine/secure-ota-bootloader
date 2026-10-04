#!/usr/bin/env node
// ============================================================================
//  Outil de signature des firmwares (côté développeur, Node.js sans dépendance)
//
//    node tools/sign.js keygen   → nouvelle paire de clés ECDSA P-256
//                                  keys/private.pem (SECRET, jamais publié)
//                                  src/public_key.h (clé publique, dans le bootloader)
//    node tools/sign.js demo     → src/demo_images.h : images de démonstration
//                                  (valides, piratées, ancienne version, boguée)
//
//  La clé privée ne quitte JAMAIS le PC du développeur : le bootloader ne
//  contient que la clé publique, qui permet de vérifier mais pas de signer.
// ============================================================================
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PRIV = path.join(ROOT, 'keys', 'private.pem');
const FW_MAGIC = 0x4d495746, HDR = 128, SIGNED = 64;

const ver = (s) => { const [a, b = 0, c = 0] = s.split('.').map(Number); return (a << 16) | (b << 8) | c; };

/** Construit une image : en-tête signé + contenu */
function buildImage({ version, name, descriptor, size = 4096, key, tamper }) {
  // Contenu : descripteur lisible par l'application + « code » pseudo-aléatoire
  const payload = Buffer.alloc(size);
  const seed = crypto.createHash('sha256').update(name).digest();
  for (let i = 0; i < size; i++) payload[i] = seed[i % 32] ^ (i * 131 & 0xff);
  Buffer.from(descriptor + '\0').copy(payload, 0);

  const hdr = Buffer.alloc(HDR);
  hdr.writeUInt32LE(FW_MAGIC, 0);
  hdr.writeUInt16LE(1, 4);
  hdr.writeUInt16LE(0, 6);
  hdr.writeUInt32LE(ver(version), 8);
  hdr.writeUInt32LE(size, 12);
  crypto.createHash('sha256').update(payload).digest().copy(hdr, 16);
  Buffer.from(name.slice(0, 15)).copy(hdr, 48);
  const sig = crypto.sign('sha256', hdr.subarray(0, SIGNED), { key, dsaEncoding: 'ieee-p1363' });
  sig.copy(hdr, 64);
  const img = Buffer.concat([hdr, payload]);
  if (tamper) tamper(img);
  return img;
}

function cArray(name, buf) {
  const lines = [];
  for (let i = 0; i < buf.length; i += 16) lines.push('  ' + [...buf.subarray(i, i + 16)].map((b) => '0x' + b.toString(16).padStart(2, '0')).join(', ') + ',');
  return `static const uint8_t ${name}[${buf.length}] = {\n${lines.join('\n')}\n};\n`;
}

function keygen() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  fs.mkdirSync(path.dirname(PRIV), { recursive: true });
  fs.writeFileSync(PRIV, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  fs.writeFileSync(path.join(ROOT, 'src', 'public_key.h'),
    '// Clé publique ECDSA P-256 du développeur (générée par tools/sign.js keygen).\n' +
    '// Publique : elle permet de VÉRIFIER une signature, pas d\'en créer.\n#pragma once\n#include <stdint.h>\n' +
    cArray('FW_PUBLIC_KEY', raw));
  console.log('✅ clés créées : keys/private.pem (secret) et src/public_key.h');
}

function demo() {
  if (!fs.existsSync(PRIV)) keygen();
  const key = crypto.createPrivateKey(fs.readFileSync(PRIV));
  const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const imgs = {
    IMG_FACTORY_V1: buildImage({ version: '1.0.0', name: 'v1.0 usine', key, descriptor: 'name=v1.0 usine;blink=1000;selftest=ok;msg=Firmware usine' }),
    IMG_V2:         buildImage({ version: '2.0.0', name: 'v2.0', key, descriptor: 'name=v2.0;blink=250;selftest=ok;msg=Nouvelle version' }),
    IMG_V3_BUGGY:   buildImage({ version: '3.0.0', name: 'v3.0 boguee', key, descriptor: 'name=v3.0 boguee;blink=80;selftest=fail;msg=Version avec un bug' }),
    // Pirate n°1 : modifie le contenu de v2 ET recalcule le hash… mais ne peut pas re-signer
    IMG_HACKED:     buildImage({ version: '2.0.0', name: 'v2.0', key, descriptor: 'name=v2.0;blink=250;selftest=ok;msg=Nouvelle version',
                      tamper: (img) => { Buffer.from('name=PIRATE;blink=50;selftest=ok;msg=Porte derobee\0').copy(img, HDR);
                                         crypto.createHash('sha256').update(img.subarray(HDR)).digest().copy(img, 16); } }),
    // Pirate n°2 : signe avec SA propre clé
    IMG_WRONG_KEY:  buildImage({ version: '9.0.0', name: 'v9.0', key: attacker, descriptor: 'name=v9.0;blink=50;selftest=ok;msg=Firmware pirate' }),
    // Retour arrière : ancienne version authentique (failles connues)
    IMG_DOWNGRADE:  buildImage({ version: '1.0.0', name: 'v1.0 usine', key, descriptor: 'name=v1.0 usine;blink=1000;selftest=ok;msg=Firmware usine' }),
  };
  let out = '// Généré par tools/sign.js demo — images de démonstration (comme si elles\n' +
            '// avaient été téléchargées depuis un serveur de mise à jour).\n#pragma once\n#include <stdint.h>\n\n';
  for (const [n, b] of Object.entries(imgs)) out += cArray(n, b) + '\n';
  fs.writeFileSync(path.join(ROOT, 'src', 'demo_images.h'), out);
  console.log('✅ src/demo_images.h :', Object.keys(imgs).join(', '));
}

const cmd = process.argv[2];
if (cmd === 'keygen') keygen();
else if (cmd === 'demo') demo();
else console.log('usage : node tools/sign.js keygen | demo');
