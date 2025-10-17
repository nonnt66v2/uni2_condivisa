/*AES-CBC stands for Advanced Encryption Standard – Cipher Block Chaining mode.
It’s one of the most common modes of operation for AES encryption.
AES itself is a block cipher — it encrypts 128 bits (16 bytes) of data at a time.
But most real data (like text, sensor values, JSON) is longer than 16 bytes
so we need a mode of operation that can handle multi-block data securely.
CBC mode does this by chaining blocks together.
Data must be padded (e.g., PKCS#7) to make its length a multiple of 16 bytes.
IV (Initialization Vector) is a random 16-byte value used only for the first block 
to make sure that even if you encrypt the same plaintext twice, you get different ciphertexts.
This example code shows AES-CBC. AES-CBC only ensures confidentiality — not integrity.
For serious projects:
An attacker could flip bits in ciphertext without detection. That’s why AES-GCM ( Galois/Counter Mode) 
is preferred for authenticated encryption.*/

#include <WiFi.h>
#include <WiFiUdp.h>
#include "DHT.h"
#include "mbedtls/aes.h"

#define DHTPIN 3
#define DHTTYPE DHT11

const char* SSID = "MYPC";
const char* PASSWORD = "123456789";
const char* RECEIVER_IP = "192.168.137.97";
const uint16_t RECEIVER_PORT = 4210;

WiFiUDP udp;
DHT dht(DHTPIN, DHTTYPE);
const uint8_t AES_KEY[16] = { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe, 0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81 }; //Must match at Receiver Node

void pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out, size_t block) {
  size_t pad = block - (in_len % block);
  memcpy(out, in, in_len);
  for (size_t i = 0; i < pad; ++i) out[in_len + i] = (uint8_t)pad;
}

size_t pkcs7_pad_len(size_t in_len, size_t block) {
  size_t pad = block - (in_len % block);
  return in_len + pad;
}

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
  delay(100);
  dht.begin();
  WiFi.setHostname("SENDER_NODE");

  WiFi.begin(SSID, PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected. IP: ");
  Serial.println(WiFi.localIP());

  udp.begin(0);
}

void loop() {
  float h = dht.readHumidity();
  float t = dht.readTemperature();
  if (isnan(h) || isnan(t)) {
    Serial.println("Failed to read DHT sensor");
    delay(2000);
    return;
  }

  char payload[128];
  int plen = snprintf(payload, sizeof(payload), "{\"t\":%.1f,\"h\":%.1f}", t, h);
  Serial.print("Plain: ");
  Serial.println(payload);

  const size_t BLOCK = 16;
  size_t padded_len = pkcs7_pad_len(plen, BLOCK);
  uint8_t plain_padded[256];
  memset(plain_padded, 0, sizeof(plain_padded));
  pkcs7_pad((uint8_t*)payload, plen, plain_padded, BLOCK);

  uint8_t iv[16];
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = esp_random();
    iv[i+0] = (r >> 0) & 0xFF;
    iv[i+1] = (r >> 8) & 0xFF;
    iv[i+2] = (r >> 16) & 0xFF;
    iv[i+3] = (r >> 24) & 0xFF;
  }

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  uint8_t cipher[256];
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);

  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, plain_padded, cipher);
  mbedtls_aes_free(&aes);

  if (ret != 0) {
    Serial.printf("AES encrypt failed: %d\n", ret);
    delay(2000);
    return;
  }

  // Print the encrypted data in HEX
  Serial.print("IV: ");
  printHex(iv, 16);
  Serial.print("Encrypted: ");
  printHex(cipher, padded_len);

  // Send packet: [IV][cipher]
  udp.beginPacket(RECEIVER_IP, RECEIVER_PORT);
  udp.write(iv, 16);
  udp.write(cipher, padded_len);
  udp.endPacket();

  Serial.printf("Sent %u bytes (IV + %u bytes ciphertext)\n\n", 16 + (unsigned)padded_len, (unsigned)padded_len);
  delay(5000);
}
