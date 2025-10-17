#include <WiFi.h>

const char* ssid = "MYPC";
const char* password = "123456789";

WiFiServer server(8080);

void setup() {
  Serial.begin(115200);
  WiFi.setHostname("Server_Node");
  WiFi.begin(ssid, password);
  Serial.print("Connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
  Serial.print("Server IP: ");
  Serial.println(WiFi.localIP());
  server.begin();
}

void loop() {
  WiFiClient client = server.available();
  if (client) {
    String data = client.readStringUntil('\n');
    if (data.length() > 0) {
      Serial.println("Received: " + data);
    }
  }
}

