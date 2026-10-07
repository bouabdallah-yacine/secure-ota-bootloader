# 🔐 Secure bootloader: signed updates, A/B slots and rollback (ESP32)

[![Tests](https://github.com/bouabdallah-yacine/secure-ota-bootloader/actions/workflows/ci.yml/badge.svg)](https://github.com/bouabdallah-yacine/secure-ota-bootloader/actions/workflows/ci.yml)

Just like a phone update: the board receives a new firmware, **verifies its digital signature**
before installing it, **rejects tampered or outdated versions**, and **automatically falls back to
the previous version** if the new one crashes. A power cut during the update can never brick the
board.

> ✅ Simulated on **Wokwi** (VS Code) with the real ESP32 flash and **mbedTLS**. The bootloader core
> is portable C, tested on a PC with OpenSSL and simulated power cuts.

## What is demonstrated

| Scenario | Result |
|---|---|
| Signed v2.0 update | ✅ installed in the inactive slot, trial boot, self-test, confirmation |
| Tampered image (modified content + recomputed hash) | ⛔ rejected: invalid signature |
| Image signed with another key | ⛔ rejected: invalid signature |
| A single bit flipped | ⛔ rejected: SHA-256 mismatch |
| Downgrade to v1.0 (authentic but old) | ⛔ rejected: anti-rollback |
| Signed but buggy v3.0 (self-test fails) | ↩️ 3 trial boots, then **automatic rollback** to v2.0 |
| Power cut while writing | ✅ the board reboots on the previous version |

**Tested:** a power cut at **each of the 73 flash operations** of a complete update
(write, trial, confirmation) → the board **always** reboots on a valid, signed image.

## How it works

```
Flash:  [ slot A: 32 KB ][ slot B: 32 KB ][ state 0 ][ state 1 ]

Image header (128 bytes): magic | version | size | SHA-256 of payload | name | ECDSA P-256 signature
```

1. **Signing** (developer PC, `tools/sign.js`): SHA-256 of the payload → stored in the header →
   the header is signed with the **private key** (ECDSA P-256). The private key never leaves the PC.
2. **Update**: the image is written to the **inactive slot**; the running firmware is never touched.
3. **Verification**: format → SHA-256 → signature with the **public key** embedded in the bootloader →
   version ≥ anti-rollback counter.
4. **Trial boot**: the new version must confirm itself after its self-test, otherwise it is rolled
   back automatically after 3 attempts.
5. **Duplicated state** (2 sectors, sequence number + CRC32): a power cut while it is being written
   always leaves one valid copy.

| File | Role |
|---|---|
| `src/bootloader.c` | boot decision, A/B slots, trial boot, rollback, anti-downgrade |
| `src/sha256.c` | portable C SHA-256 (checked against NIST test vectors) |
| `src/main.cpp` | ESP32: real flash (`esp_partition`), ECDSA with mbedTLS, OLED, menu, web server |
| `src/web_page.h` | embedded web dashboard (light / dark theme) |
| `tools/sign.js` | key generation and image signing (Node.js, no dependencies) |
| `test/test_bootloader.c` | 15 tests: attacks, rollback, power cuts |

## Running the demo (Wokwi in VS Code)

1. Open this folder in VS Code → PlatformIO **Build** → **F1 › Wokwi: Start Simulator**.
2. On first boot, the v1.0 factory firmware is installed and verified.
   Open **http://localhost:8183**: the dashboard (running firmware, A/B slots, log, scenario
   buttons). Everything can be done from the page or from the serial monitor.
3. In the serial monitor, type:
   - `1`: v2.0 update → reboot → self-test → confirmed, the LED blinks faster;
   - `3` or `4`: tampered images → **rejected**, the red LED blinks;
   - `5`: downgrade to v1.0 → **rejected**;
   - `2`: buggy v3.0 → it crashes 3 times → **automatic rollback** to v2.0;
   - `6`: power cut at 50% → the board reboots on the previous version;
   - `s`: slot status, `e`: factory reset.

> In the simulator, the ESP32 cannot execute downloaded code: the image carries the application
> configuration (blink rate, message, self-test). On a real board, the bootloader would jump to the
> slot address (the MCUboot approach). The security logic is the same.

## Tests

```bash
gcc -O2 -Wall -Wextra -Isrc -o t test/test_bootloader.c src/bootloader.c src/sha256.c -lcrypto && ./t
```

## Signing your own images

```bash
node tools/sign.js keygen   # new key pair (keys/private.pem stays on your PC)
node tools/sign.js demo     # regenerates src/demo_images.h with your key
```

## License

© 2026 Yacine — all rights reserved. Code published for viewing only (see [`LICENSE`](LICENSE)).
