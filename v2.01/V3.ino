

/**
 * Copyright (c) 2017, Łukasz Marcin Podkalicki <lpodkalicki@gmail.com>
 * ESP32/016
 * WiFi Sniffer.
 */


/**
 * Changed and Used by NamacilHDx 
 * 
 * Origin: https://blog.podkalicki.com/esp32-wifi-sniffer/
 * 
 * My Channel: https://www.youtube.com/channel/UCT3zKa1xF6fV_7jMOSrO_TA/featured
 * 
 * THX <3 
 * 
 */




//_____________________ SETTINGS ___________________

#define UPDATE_EVERY_XX_PACKAGES 20
#define PACKAGE_INSIGHT_MODE true // show detailed info about the Package/ See the Original for even more insight
#define MAKE_LISTING false // Show listing every XX "after that, asap" "seen" packages/ <---- currently out of order
#define INTERPRETING_PACKAGES true
#define PRINT_BINARY_OCTETTS false 
#define PRINT_HEX_BYTES true
#define STICK_TO_ONE_CHANNEL 6 // Type in the Channel of your Choice. if you want to hop channels in regular time intervals, type something wich is not a channel X > 13 for example


// __________________________________________________

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

// Temperatur Sensor
#ifdef __cplusplus
  extern "C" {
 #endif

  uint8_t temprature_sens_read();

#ifdef __cplusplus
}
#endif

uint8_t level = 0;
uint8_t channel = STICK_TO_ONE_CHANNEL;
static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct
uint8_t temprature_sens_read();

String temp; // varaible for building a string from Hex Digits 

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event){
  return ESP_OK;
}
void wifi_sniffer_set_channel(uint8_t channel){
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void setup() {
  Serial.begin(250000);
  
  delay(20);
  
  // wifi init:
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  delay(20);
  
  wifi_sniffer_set_channel(constrain(channel,0,13));
}

void loop() {
  float temprature = (temprature_sens_read()  - 32) / 1.8;
  if(temprature > 55){
    Serial.println();
    Serial.println(String(temprature) + " C° !");
  }
  
// put some sort of smart Channel Switching here!

  if(STICK_TO_ONE_CHANNEL > 13){
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
  }
}


String HexToString(int In){ // this takes a Number and turnes into a Hex String with always 2 digits
 String in = String(In,HEX);
  if(String(in.charAt(1)) == ""){
  in = "0" + in;
  }
  return in;
}

String FindType(int a){
      switch (a){ // This is checking for the Type of package that was being send
    case 0b000000:
      return ("Association Request");
    break;
    case 0b000001:
      return ("Association Response");
    break;
    case 0b000010:
      return ("Reassociation Request");
    break;
    case 0b000011:
      return ("Reassociation Response");
    break;
    case 0b000100:
      return ("Probe Request");
    break;
    case 0b000101:
      return ("Probe Response");
    break;
    case 0b000110:
      return ("Timing Advertisement");
    break;
    case 0b000111:
      return ("Reserved");
    break;
    case 0b001000:
      return ("Beacon");
    break;
    case 0b001001:
      return ("Announcement Traffic Indication Message");
    break;
    case 0b001010:
      return ("Disassociation");
    break; 
    case 0b001011:
      return ("Authentication");
    break; 
    case 0b001100:
      return ("Deauthentication");
    break;
    case 0b001101:
      return ("Action");
    break; 
    case 0b001110:
      return ("Action No Ack (NACK)");
    break;         
    case 0b010010:
      return ("Trigger");
    break;         
    case 0b010011:
      return ("TACK");
    break;         
    case 0b010100:
      return ("Beamforming Report Poll");
    break;         
    case 0b010101:
      return ("VHT/HE NDP Announcement");
    break;         
    case 0b010110:
      return ("Control Frame Extension");
    break;         
    case 0b010111:
      return ("Control Wrapper");
    break;              
    case 0b011000:
      return ("Block Ack Request (BAR)");
    break;         
    case 0b011001:
      return ("Block Ack (BA)");
    break;         
    case 0b011010:
      return ("PS-Poll");
    break;         
    case 0b011011:
      return ("Request To Send ");
    break;         
    case 0b011100:
      return ("Clear To Send");
    break;         
    case 0b011101:
      return ("Acknowledgement");
    break;         
    case 0b011110:
      return ("CF-End");
    break;         
    case 0b011111:
      return ("CF-End + CF-ACK");
    break;         
    case 0b100000:
      return ("Data");
    break;         
    case 0b100001:
      return ("Data + CF-ACK");
    break;         
    case 0b100010:
      return ("Data + CF-Poll");
    break;         
    case 0b100011:
      return ("Data + CF-ACK + CF-Poll");
    break;         
    case 0b100100:
      return ("Null (no data)");
    break;         
    case 0b100101:
      return ("CF-ACK (no data)");
    break;         
    case 0b100110:
      return ("CF-Poll (no data)");
    break;         
    case 0b100111:
      return ("CF-ACK + CF-Poll (no data)");
    break;         
    case 0b101000:
      return ("QoS Data");
    break;         
    case 0b101001:
      return ("QoS Data + CF-ACK");
    break;         
    case 0b101010:
      return ("QoS Data + CF-Poll");
    break;
    case 0b101011:
      return ("QoS Data + CF-ACK + CF-Poll");
    break;           
    case 0b101100:
      return ("QoS Null (no data)");
    break;           
    case 0b101101:
      return ("Reserved");
    break;           
    case 0b101110:
      return ("QoS CF-Poll (no data)");
    break;           
    case 0b101111:
      return ("QoS CF-ACK + CF-Poll (no data)");
    break;           
    case 0b110000:
      return ("DMG Beacon");
    break;           
    case 0b110001:
      return ("S1G Beacon");
    break;           
    default:
      return ("Unknown/Specifiyed");
    break;           
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type){ //This is the Call when ever a Package goes by.
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  
  String ppkgSSID = "";
  uint16_t CapabilityInfo = 0;
  double Temp = (temprature_sens_read() - 32) / 1.8;
  
  uint8_t ToDs_FromDs = (ppkt->payload[1] & 0b11000000) >> 6;
  String PPktType = FindType(ppkt->payload[0] & 0b00111111);
  int CurChannel = (ppkt->rx_ctrl.channel);

  Serial.print("|");

  
  if(PACKAGE_INSIGHT_MODE & PPktType != "Association Request"){
    
  Serial.println();//Do the Actuall interpreting part
    if(PRINT_HEX_BYTES){ // This prints out the Package in HEX for demostraion or debugging
      for(int u; u < 100; u++){
        Serial.print(HexToString(ppkt->payload[u]) + " ");
      }
    }
    if(PRINT_BINARY_OCTETTS){ // This prints out the Package in Binary for demostraion or debugging
      for(int i; i < 100;i++){
        temp = String(ppkt->payload[i],BIN);
        while(temp.length() < 8){
          temp = "0" + temp;
        }
        Serial.print(temp + " ");  
      }
    }
    
    
    Serial.println();
    Serial.println("Type                                : " + PPktType);
    Serial.println("Channel                             : " + String(CurChannel));

    switch (ToDs_FromDs){ // This is checking for the Adress Configuration of the Package and Printing it.
    case 0:
      Serial.print("Recieving/Destination(RA/DA) Adress : ");
      for(int i = 4; i < 10;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Transmitting/Source Adress (TA/SA)  : ");
      for(int i = 10; i < 16;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("BSSID (AP MAC)                      : ");
      for(int i = 16; i < 22;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }            
    break;
    case 1:
      Serial.print("Recieving/Destination(RA/DA) Adress : ");
      for(int i = 4; i < 10;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Transmitting Adress/ AP Mac (BSSID) : ");
      for(int i = 10; i < 16;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Source Adress (SA)                  : ");
      for(int i = 16; i < 22;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }            
    break;
    case 2:
      Serial.print("Recieving Adress/AP Mac (RA/BSSID)  : ");
      for(int i = 4; i < 10;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Transmitting Adress/ AP Mac (BSSID) : ");
      for(int i = 10; i < 16;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Source Adress (SA)                  : ");
      for(int i = 16; i < 22;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }           
    break;
    case 3:
      Serial.print("Recieving Adress (RA)                : ");
      for(int i = 4; i < 10;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Transmitting Adress (TA)             : ");
      for(int i = 10; i < 16;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Destination Adress (DA)               : ");
      for(int i = 16; i < 22;i++){
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }
      Serial.println();
      Serial.print("Source Adress (SA)                    : ");
      for(int i = 24; i < 30;i++){ //                                 <---- These Byte might still be wrong
        Serial.print(HexToString(ppkt->payload[i]) + " "); 
      }           
      break;
    }
    Serial.println();  
    
    if(PPktType == "Association Request"){
      
      // x - 38<-SSID  37 <- SSIDL 36 <- ElementID 35 34 32 31 30 29 28 27 <- Timestamp  26 25 <- status code 24 23 <- reason code
      uint8_t SSIDLenght = ppkt->payload[37];
      for(int i = 0; i < SSIDLenght;i++){
        ppkgSSID = ppkgSSID + char(ppkt->payload[i+38]); 
      }
      Serial.println("SSID                                : " + ppkgSSID);
    }

    if(PPktType == "Beacon"){
      //Serial.println(sizeof(ppkt->payload));
      // x - 38<-SSID  37 <- SSIDL 36 <- ElementID 35 34 <- capability info 32 31<- beacon interval  30 29 28 27 26 25 24 23 Timestamp
      uint8_t SSIDLenght = ppkt->payload[37];
      //for(int i = 0; i < SSIDLenght;i++){
      for(int i = 38; i < 40;i++){
        //Serial.print(char(ppkt->payload[i]));
        //ppkgSSID = ppkgSSID + char(ppkt->payload[i]); //+38
      }
      //Serial.println("SSID                                : " + ppkgSSID);
      
      uint64_t TimeStamp = ppkt->payload[23] | (ppkt->payload[24]<<8*1) | (ppkt->payload[25]<<16) | (ppkt->payload[26]<<24) | (ppkt->payload[27]<<32) | (ppkt->payload[28]<<40) | (ppkt->payload[29]<<48) | (ppkt->payload[30]<<56);
      Serial.println("TimeStamp in Minuts                 : " + uint32_t (TimeStamp/3600));
       




    }
  
  
  
  
  
  }
}





/*
 * 
 * 
 * 
 * 
 *     uint64_t TimeStamp = ppkt->payload[27] | (ppkt->payload[28]<<8*1) | (ppkt->payload[29]<<16) | (ppkt->payload[30]<<24) | (ppkt->payload[31]<<32) | (ppkt->payload[32]<<40) | (ppkt->payload[33]<<48) | (ppkt->payload[34]<<56)
    Serial.println("TimeStamp in Minuts")
      // - 38<- 0 - 32B SSID  37 <- SSIDL 36 35 34 32 31 30 29 28 <- Timestamp 27 26 <- status code  25 24 <- reason code
      
      ppktStatus = (ppkt->payload[26]<<8) | ppkt->payload[25];
      Serial.print("Status Code:  ");
      switch(ppktStatus){ // switch case for finding statuscode for  arequest Association Request
        case 0:
          Serial.println("sucsessful");
        break;
        case 1: 
          Serial.println("unspecified failure");
        break;
        case 10: 
          Serial.println("Cannot support all requested capabilities in the Capability Information field");
        break;
        case 11: 
          Serial.println("Reassociation denied due to inability to confirm that association exists");
        break;
        case 12: 
          Serial.println("Association denied due to reason outside the scope of this standard");
        break;
        case 13: 
          Serial.println("Responding station does not support the specified authentication algorithm");
        break;
        case 14: 
          Serial.println("Received an Authentication frame with authentication transaction sequence number out of expected sequence");
        break;
        case 15: 
          Serial.println("Authentication rejected because of challenge failure ");
        break;
        case 16: 
          Serial.println("Authentication rejected due to timeout waiting for next frame in sequence");
        break;
        case 17: 
          Serial.println("Association denied because the access point isunable to handle additional associated stations");
        break;
        case 18: 
          Serial.println("Association denied due to requesting station not supporting all of the data rates in the BSSBasicRateSet parameter ");
        break;
        case 19: 
          Serial.println("Association denied due to requesting station not supporting the Short Preamble option ");
        break;
        case 20: 
          Serial.println("Association denied due to requesting station not supporting the PBCC Modulation option");
        break;
        case 21: 
          Serial.println("Association denied due to requesting station not supporting the Channel Agility option");
        break;
        case 25: 
          Serial.println("Association denied due to requesting station not supporting the Short Slot Time option");
        break;
        case 26: 
          Serial.println("Association denied due to requesting station not supporting the DSSS-OFDM option");
        break;
        default:
          Serial.println(ppktStatus,BIN);
        break;
      }

      ppktReason = (ppkt->payload[24]<<8) | ppkt->payload[23];
      Serial.print("Reason Code:  ");
      switch(ppktReason){ // switch case for finding reason for  arequest Association Request
        case 1: 
          Serial.println("Unspecified reason");
        break;
        case 2: 
          Serial.println("Previous authentication no longer valid ");
        break;
        case 3: 
          Serial.println("Deauthenticated because sending station is leaving (or has left) IBSS or ESS ");
        break;
        case 4: 
          Serial.println("Disassociated due to inactivity");
        break;
        case 5: 
          Serial.println("Disassociated because the access point is unable to handle all currently associated stations");
        break;
        case 6: 
          Serial.println("Class 2 frame received from non-authenticated station");
        break;
        case 7: 
          Serial.println("Class 3 frame received from non-associated station");
        break;
        case 8: 
          Serial.println("Disassociated because sending station is leaving (or has left) BSS");
        break;
        case 9: 
          Serial.println("Station requesting (re)association is not authenticated with responding station");
        break;
        default:
          Serial.println(ppktReason,BIN);
        break;
      }

*/
