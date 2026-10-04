# 🔐 Bootloader sécurisé : mise à jour signée, slots A/B et retour arrière (ESP32)

Comme la mise à jour d'un téléphone : la carte reçoit un nouveau firmware, **vérifie sa signature
numérique** avant de l'installer, **refuse les versions piratées ou trop anciennes**, et **revient toute
seule à l'ancienne version** si la nouvelle plante. Une coupure de courant pendant la mise à jour ne
peut jamais rendre la carte inutilisable.

> ✅ Simulé sur **Wokwi** (VS Code) avec la vraie flash de l'ESP32 et **mbedTLS**. Le cœur du bootloader
> est du C portable, testé sur PC avec OpenSSL et des coupures de courant simulées.

## Ce qui est démontré

| Scénario | Résultat |
|---|---|
| Mise à jour v2.0 signée | ✅ installée dans le slot inactif, démarrage d'essai, autotest, confirmation |
| Image piratée (contenu modifié + hash recalculé) | ⛔ refusée : signature invalide |
| Image signée par une autre clé | ⛔ refusée : signature invalide |
| Un seul bit modifié | ⛔ refusée : SHA-256 incorrect |
| Retour à v1.0 (authentique mais ancienne) | ⛔ refusé : anti-retour arrière |
| v3.0 signée mais boguée (autotest échoue) | ↩️ 3 démarrages d'essai puis **retour automatique** à v2.0 |
| Coupure de courant pendant l'écriture | ✅ la carte redémarre sur l'ancienne version |

**Testé :** coupure de courant à **chacune des 73 opérations flash** d'une mise à jour complète
(écriture, essai, confirmation) → la carte redémarre **toujours** sur une image valide et signée.

## Comment ça marche

```
Flash :  [ slot A : 32 Ko ][ slot B : 32 Ko ][ état 0 ][ état 1 ]

En-tête d'image (128 octets) : magic | version | taille | SHA-256 du contenu | nom | signature ECDSA P-256
```

1. **Signature** (PC du développeur, `tools/sign.js`) : SHA-256 du contenu → placé dans l'en-tête →
   l'en-tête est signé avec la **clé privée** (ECDSA P-256). La clé privée ne quitte jamais le PC.
2. **Mise à jour** : l'image est écrite dans le **slot inactif** ; le firmware en service n'est jamais touché.
3. **Vérification** : format → SHA-256 → signature avec la **clé publique** gravée dans le bootloader →
   version ≥ compteur anti-retour arrière.
4. **Démarrage d'essai** : la nouvelle version doit se confirmer après son autotest, sinon retour arrière
   automatique après 3 tentatives.
5. **État en double exemplaire** (2 secteurs, numéro de séquence + CRC32) : une coupure pendant son
   écriture laisse toujours une copie valide.

| Fichier | Rôle |
|---|---|
| `src/bootloader.c` | décision de démarrage, slots A/B, essai, retour arrière, anti-downgrade |
| `src/sha256.c` | SHA-256 en C portable (vérifié avec les vecteurs du NIST) |
| `src/main.cpp` | ESP32 : flash réelle (`esp_partition`), ECDSA avec mbedTLS, OLED, menu, serveur web |
| `src/web_page.h` | dashboard web embarqué (thème clair / sombre) |
| `tools/sign.js` | génération des clés et signature des images (Node.js, sans dépendance) |
| `test/test_bootloader.c` | 15 tests : attaques, retour arrière, coupures de courant |

## Lancer la démo (Wokwi dans VS Code)

1. Ouvre ce dossier dans VS Code → PlatformIO **Build** → **F1 › Wokwi: Start Simulator**.
2. Au premier démarrage, le firmware usine v1.0 est installé et vérifié.
   Ouvre **http://localhost:8183** : le dashboard (firmware en service, slots A/B, journal, boutons des
   scénarios). Tu peux tout faire depuis la page ou depuis le moniteur série.
3. Dans le moniteur série, tape :
   - `1` : mise à jour v2.0 → redémarrage → autotest → confirmée, la LED clignote plus vite ;
   - `3` ou `4` : images piratées → **refusées**, la LED rouge clignote ;
   - `5` : retour à v1.0 → **refusé** ;
   - `2` : v3.0 boguée → elle plante 3 fois → **retour automatique** à v2.0 ;
   - `6` : coupure de courant à 50 % → la carte redémarre sur la version précédente ;
   - `s` : état des slots, `e` : retour usine.

> Dans le simulateur, l'ESP32 ne peut pas exécuter du code téléchargé : l'image contient la configuration
> de l'application (clignotement, message, autotest). Sur une vraie carte, le bootloader sauterait à
> l'adresse du slot (principe de MCUboot). La logique de sécurité est la même.

## Tests

```bash
gcc -O2 -Wall -Wextra -Isrc -o t test/test_bootloader.c src/bootloader.c src/sha256.c -lcrypto && ./t
```

## Signer tes propres images

```bash
node tools/sign.js keygen   # nouvelle paire de clés (keys/private.pem reste sur ton PC)
node tools/sign.js demo     # régénère src/demo_images.h avec ta clé
```
