#include <WiFi.h>
#include "esp_tls.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include "ca_cert.h"     // Root CA certificate
#include "client_cert.h" // Client certificate
#include "client_key.h"  // Client private key

const char* ssid = "MYPC";
const char* password = "123456789";
#define SERVER_PORT 8443

const char* server_ip = "192.168.137.153"; // Change this to your server's actual IP

void setup() {
  Serial.begin(115200);
  delay(1000);
   WiFi.setHostname("ESP32-TLS-CLIENT");
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi ");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());
  
  // Start TLS client task
  xTaskCreatePinnedToCore(tlsClientTask, "tls_client", 8192, NULL, 5, NULL, 0);
}

void loop() {
  delay(1000);
}

//TLS client task with client certificate
void tlsClientTask(void *pvParameters) {
  const char *TAG = "TLS_CLIENT";
  
  while (true) {
    Serial.printf("\n[%s] Attempting to connect to server %s:%d...\n", TAG, server_ip, SERVER_PORT);

    //TLS configuration with client certificates
    esp_tls_cfg_t cfg = {};
    // Server certificate verification
    cfg.cacert_buf = (const unsigned char*)ca_cert_pem;
    cfg.cacert_bytes = ca_cert_pem_len;
    cfg.skip_common_name = true; // CN verification
    
    // Client certificate authentication
    cfg.clientcert_buf = (const unsigned char*)client_cert_pem;
    cfg.clientcert_bytes = client_cert_pem_len;
    cfg.clientkey_buf = (const unsigned char*)client_key_pem;
    cfg.clientkey_bytes = client_key_pem_len;
    
    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
      Serial.printf("[%s] esp_tls_init failed\n", TAG);
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    }

    // Connect with TLS and client certificate
    int ret = esp_tls_conn_new_sync(server_ip, strlen(server_ip), SERVER_PORT, &cfg, tls);
    
    if (ret == 1) { // 1 means success
      Serial.printf("[%s] TLS handshake successful! Client certificate authenticated.\n", TAG);

      // Read welcome message from server
      char buffer[256];
      int len = esp_tls_conn_read(tls, buffer, sizeof(buffer) - 1);
      if (len > 0) {
        buffer[len] = 0;
        Serial.printf("[%s] Server says: %s", TAG, buffer);
      }


      int message_count = 0;
      while (true) {
        // Send message to server
        char message[64];
        snprintf(message, sizeof(message), "Hello from authenticated client! Message #%d\n", ++message_count);
        
        ret = esp_tls_conn_write(tls, message, strlen(message));
        if (ret < 0) {
          Serial.printf("[%s] Write error: 0x%x\n", TAG, ret);
          break;
        }
        Serial.printf("[%s] Sent: %s", TAG, message);

        // Receive response from server
        len = esp_tls_conn_read(tls, buffer, sizeof(buffer) - 1);
        if (len > 0) {
          buffer[len] = 0;
          Serial.printf("[%s] Received: %s", TAG, buffer);
        } else if (len == 0 || len == MBEDTLS_ERR_SSL_WANT_READ || len == MBEDTLS_ERR_SSL_WANT_WRITE) {
          continue;
        } else if (len == MBEDTLS_ERR_SSL_CONN_EOF) {
          Serial.printf("[%s] Server closed connection\n", TAG);
          break;
        } else {
          Serial.printf("[%s] Read error: 0x%x\n", TAG, len);
          break;
        }

        vTaskDelay(2000 / portTICK_PERIOD_MS); // Send message every 2 seconds
      }

    } else {
      Serial.printf("[%s] Connection failed: 0x%x\n", TAG, ret);
      
      // Troubleshooting
      if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
        Serial.printf("[%s] TLS handshake timeout\n", TAG);
      } else if (ret == MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE) {
        Serial.printf("[%s] TLS handshake failed - check certificates\n", TAG);
      } else if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        Serial.printf("[%s] Certificate verification failed\n", TAG);
      //} else if (ret == MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO) {
       // Serial.printf("[%s] Bad client hello\n", TAG);
      } else if (ret == MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME) {
        Serial.printf("[%s] Unrecognized server name\n", TAG);
      }
    }

    // Cleanup
    if (tls) {
      esp_tls_conn_destroy(tls);
    }
    
    Serial.printf("[%s] Connection closed. Retrying in 5 seconds...\n", TAG);
    vTaskDelay(5000 / portTICK_PERIOD_MS);
  }
}