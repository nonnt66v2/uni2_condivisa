#include <WiFi.h>
#include "DHT.h"

#define DHTPIN 3       
#define DHTTYPE DHT11   
DHT dht(DHTPIN, DHTTYPE);

const char* ssid = "MYPC";
const char* password = "123456789";
const char* host = "192.168.137.8";
const int port = 8080;

WiFiClient client;

void setup() {
  Serial.begin(115200);
  dht.begin();
  WiFi.setHostname("Client_Node");
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

void loop() {

  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();
  if (isnan(temp) || isnan(hum)) {
    Serial.println("Failed to read from DHT sensor!");
    return;
  }
  // String Values
  if (client.connect(host, port)) {
  String message = "Temperature: " + String(temp, 2) + " °C, Humidity: " + String(hum, 2) + " %";
  client.println(message);
  Serial.println("Sent:" + message);
  client.stop();
  } else {
    Serial.println("Connection failed");
  }
  
  delay(1000);
}


