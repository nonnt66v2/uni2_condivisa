#include <WiFi.h>
#include <WiFiUdp.h>
#include "mbedtls/aes.h"

const char* SSID = "MYPC";
const char* PASSWORD = "123456789";

const uint16_t LISTEN_PORT = 4210;
WiFiUDP udp;

const uint8_t AES_KEY[16] = { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe, 0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81 };

// helper to print bytes in hex
void printHex(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] < 0x10) Serial.print("0");
    Serial.print(buf[i], HEX);
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  WiFi.setHostname("RECEIVER_NODE");
  delay(100);

  WiFi.begin(SSID, PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected. IP: ");
  Serial.println(WiFi.localIP());

  udp.begin(LISTEN_PORT);
  Serial.printf("Listening on UDP port %d\n", LISTEN_PORT);
}

void loop() {
  int packetSize = udp.parsePacket();
  if (packetSize > 0) {
    uint8_t buffer[512];
    int len = udp.read(buffer, sizeof(buffer));
    if (len <= 16) return;

    uint8_t iv[16];
    memcpy(iv, buffer, 16);
    uint8_t *cipher = buffer + 16;
    size_t cipher_len = len - 16;

    Serial.printf("Received %d bytes (IV + ciphertext)\n", len);
    Serial.print("IV: ");
    printHex(iv, 16);
    Serial.print("Encrypted: ");
    printHex(cipher, cipher_len);

    // Decrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    uint8_t decrypted[512];
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipher_len, iv_copy, cipher, decrypted);
    mbedtls_aes_free(&aes);

    if (ret != 0) {
      Serial.printf("AES decrypt failed: %d\n", ret);
      return;
    }

    // Remove PKCS7 padding
    uint8_t pad = decrypted[cipher_len - 1];
    size_t plain_len = cipher_len - pad;
    decrypted[plain_len] = '\0';

    Serial.print("Decrypted: ");
    Serial.println((char*)decrypted);
    Serial.println();
  }
}
