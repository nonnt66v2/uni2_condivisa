#include <WiFi.h>
#include "esp_tls.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include "mbedtls/ssl.h"
#include "cert.h"  // server certificate
#include "key.h"   // private key/key certificate
#include "ca_cert.h" // root certificate


const char* ssid = "MYPC";
const char* password = "123456789";
#define SERVER_PORT 8443

void setup() {
  Serial.begin(115200);
  delay(1000);
   WiFi.setHostname("ESP32-TLS-SERVER");
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi ");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());
  xTaskCreatePinnedToCore(tlsServerTask, "tls_server", 8192, NULL, 5, NULL, 0);
}

void loop() {
  delay(1000);
}

// ===== TLS Server Task =====
void tlsServerTask(void *pvParameters) {
  const char *TAG = "TLS_SERVER";
  struct sockaddr_in server_addr, client_addr;
  socklen_t addr_len = sizeof(client_addr);
  int sock_listen, sock_client;

  sock_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (sock_listen < 0) {
    Serial.printf("[%s] Socket create failed\n", TAG);
    vTaskDelete(NULL);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sock_listen, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    Serial.printf("[%s] Bind failed\n", TAG);
    close(sock_listen);
    vTaskDelete(NULL);
  }

  listen(sock_listen, 1);
  Serial.printf("[%s] Listening on port %d...\n", TAG, SERVER_PORT);

  while (true) {
    sock_client = accept(sock_listen, (struct sockaddr *)&client_addr, &addr_len);
    if (sock_client < 0) {
      Serial.printf("[%s] Accept failed\n", TAG);
      continue;
    }

    Serial.printf("[%s] Client connected. Starting TLS handshake...\n", TAG);

    // --- TLS configuration ---
    esp_tls_cfg_server_t cfg = {};
      cfg.servercert_buf   = (const unsigned char*)server_cert_pem;
      cfg.servercert_bytes = server_cert_pem_len;
      cfg.serverkey_buf    = (const unsigned char*)server_key_pem;
      cfg.serverkey_bytes  = server_key_pem_len;
      cfg.cacert_buf       = (const unsigned char*)ca_cert_pem;
      cfg.cacert_bytes     = ca_cert_pem_len;
    
    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
      Serial.printf("[%s] esp_tls_init failed\n", TAG);
      close(sock_client);
      continue;
    }
    //Session create
    int ret = esp_tls_server_session_create(&cfg, sock_client, tls);
    if (ret == 0 || ret == 1) {
      Serial.printf("[%s] TLS handshake successful! (return code: %d)\n", TAG, ret);
 const char *reply = "Hello From TLS secure server!\n";
            esp_tls_conn_write(tls, reply, strlen(reply));

            // --- Echo loop (clean, no duplicates) ---
            char rx_buffer[256];
            while (true) {
                int len = esp_tls_conn_read(tls, rx_buffer, sizeof(rx_buffer) - 1);

                if (len > 0) {
                    rx_buffer[len] = 0; // null-terminate for printing
                    Serial.printf("[%s] Received %d bytes: %s\n", TAG, len, rx_buffer);

                    // Echo back exactly what we got
                    //esp_tls_conn_write(tls, rx_buffer, len);
                } else if (len == 0 || len == MBEDTLS_ERR_SSL_CONN_EOF) {
                    // Client closed connection gracefully
                    Serial.printf("[%s] Client disconnected gracefully\n", TAG);
                    break;

                } else if (len == ESP_TLS_ERR_SSL_WANT_READ || len == ESP_TLS_ERR_SSL_WANT_WRITE) {
                    // No data yet, continue polling
                    delay(10);
                    continue;

                } else {
                    // Real read error
                    Serial.printf("[%s] TLS read error: %d\n", TAG, len);
                    break;
                }
            }

        } else {
            Serial.printf("[%s] TLS handshake failed with error: %d\n", TAG, ret);
        }

        // Cleanup
        if (tls) {
            esp_tls_server_session_delete(tls);
        }
        close(sock_client);
        Serial.printf("[%s] Connection closed.\n\n", TAG);
    }
}