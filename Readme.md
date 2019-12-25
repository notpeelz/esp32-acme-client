House alarm system based on ESP32

Copyright (c) 2017, 2018, 2019 by Danny Backx

This alarm system is designed to work with a bunch of similar controllers.
You can choose which hardware and capabilities go in each individual controller, and configure them accordingly.

The software needs a small amount of configuration to talk to the hardware.
Currently setup is to hardcode, partially as a security measure, configuration (small JSON texts).
An evolution could be to add GUI to configure modules via the touch screen.
No (network) remote configuration functionality is built-in, to prevent making the system hackable.

It needs to be built with ESP-IDF, the build environment recommended by Espressif.

Components required (you need to put these in components/) :
- arduino (https://github.com/espressif/arduino-esp32.git)
- espmqtt : this is no longer a separate requirement, it became part of esp-idf (from v3.2).

Arduino libraries (these are already copied in libraries/) :
- TFT_eSPI (Bodmer's stuff with small changes)
- Timezone
- arduinojson
- rcswitch
- rfid

Hardware platform :
 - ESP8266 and/or ESP32
   Choose what you like, have, or need. Most importantly : the ESP32 has more pins.
   An ESP8266 with an OLED and a radio is out of pins, if you need to put more hardware in one box, you need an ESP32.
   An ESP8266 with OLED and PN532 card reader also has just enough pins.
 - Some sensors with wireless RF communication
   * https://www.aliexpress.com/item/Kerui-433MHz-Wireless-Intelligent-PIR-Sensor-Motion-Detector-For-GSM-PSTN-Security-Alarm-System-Auto-Dial/32566190623.html?spm=a2g0
s.9042311.0.0.04PnSB
   * https://www.aliexpress.com/item/433MHz-Portable-Alarm-Sensors-Wireless-Fire-Smoke-Detector/32593947430.html?spm=a2g0s.9042311.0.0.04PnSB
 - Keypads with touch displays
   * https://www.aliexpress.com/item/1pcs-J34-F85-240x320-2-8-SPI-TFT-LCD-Touch-Panel-Serial-Port-Module-with-PCB/32795636902.html?spm=a2g0s.9042311.0.0.04PnSB
 - RF receivers
   * https://www.aliexpress.com/item/1set-2pcs-RF-wireless-receiver-module-transmitter-module-board-Ordinary-super-regeneration-433MHZ-DC5V-ASK-OOK/32606396563.html?spm
=a2g0s.9042311.0.0.04PnSB
 - RFID card readers
   * https://www.aliexpress.com/item/2pcs-lot-MFRC-522-RC522-RFID-Kits-S50-13-56-Mhz-With-Tags-SPI-Write-Read/32620671237.html?spm=a2g0s.9042311.0.0.tm7J7e
   * https://www.aliexpress.com/item/PN532-NFC-RFID-Module-V3-Kits-Reader-Writer/32452824672.html?spm=a2g0s.9042311.0.0.XugjzW

I have a PCB design that can be used to build a controller module with minimal wiring.
See my project on easyeda.com, or the copy in pcb .
The v1 has one known bug : the radio data line should go to esp32 pin 27 instead of pin 22.


Note : you may need to set some parameters in "make menuconfig" to make this work
- CONFIG_SYSTEM_EVENT_TASK_STACK_SIZE=4304 (was 2304)
  to prevent eventTask from running out of stack space
- CONFIG_FREERTOS_USE_TRACE_FACILITY=y if you want to be able to list the ESP32 tasks,
  or their memory/stack usage
  (menuconfig->Component config->FreeRTOS->Enable FreeRTOS trace facility)
