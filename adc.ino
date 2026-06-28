#include <Wire.h>
#include <Adafruit_ADS1X15.h>

Adafruit_ADS1015 ads;

void setup() {
  Serial.begin(115200);

  if (!ads.begin()) {
    Serial.println("ERROR: ADS1015 not found! Check wiring.");
    while (1);
  }

  ads.setGain(GAIN_TWOTHIRDS);
  ads.setDataRate(RATE_ADS1015_3300SPS);  // Max sample rate
}

void loop() {
  int16_t rawADC = ads.readADC_SingleEnded(0);

  if (rawADC < 0) rawADC = 0;

  // Print all 12 bits continuously with NO spaces, NO newline
  for (int i = 11; i >= 0; i--) {
    Serial.print((rawADC >> i) & 1);
  }

  // No Serial.println() — keeps it as one endless string
}