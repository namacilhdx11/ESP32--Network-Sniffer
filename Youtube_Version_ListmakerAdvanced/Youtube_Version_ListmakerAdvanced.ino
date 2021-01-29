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
#define MAKE_LISTING false // Show listing every XX "after that, asap" "seen" packages/
#define INTERPRETING_PACKAGES true
#define PRINT_BINARY_OCTETTS true 


// __________________________________________________






#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define LED_GPIO_PIN                     2
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)



uint8_t level = 0, channel = 1;


static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

String temp;


typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event){
  return ESP_OK;
}

void wifi_sniffer_init(void){
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
}

void wifi_sniffer_set_channel(uint8_t channel){
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type){
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

const int DeviceAnount = 200;



double   DeviceSents[DeviceAnount];
float DeviceRssi[DeviceAnount];
String Devices[DeviceAnount];
String tempDevice="";
bool isNew;
int haventPrintedSince = 0;
int Highest=0; 

String HexToString(int In){
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

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type){
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  Serial.println();
  
  tempDevice="";
  for(int i = 0; i < 6;i++){
    tempDevice = tempDevice + HexToString(hdr->addr2[i]) + " "; 
  }

  isNew = true;
  for(int i = 0; i < DeviceAnount;i++){
    if(tempDevice == Devices[i]){
      isNew = false;
      if(MAKE_LISTING){
        Serial.println("Known Device Updated");
      }
      DeviceRssi[i] += (ppkt->rx_ctrl.rssi-DeviceRssi[i])/10.00;
      DeviceSents[i] += 1;
      haventPrintedSince++;
      if(PACKAGE_INSIGHT_MODE){// Device Known! Show Insights
        Serial.println();
        Serial.println();
        for(int u; u < 100; u++){
          Serial.print(HexToString(ppkt->payload[u]) + " ");
        }
        Serial.println();
        Serial.print(" Sender: ");
        for(int i = 0; i < 6;i++){
          Serial.print(HexToString(hdr->addr2[i]) + " "); 
        }
        Serial.print(" Target: ");
        for(int i = 0; i < 6;i++){
          Serial.print(HexToString(hdr->addr1[i]) + " "); 
        }
        Serial.println();
        Serial.println();
      }
      break;
    }
  }
  if(isNew){
      for(int i = 0; i < DeviceAnount;i++){
        if(Devices[i] == ""){
          Devices[i] = tempDevice;
          if(MAKE_LISTING){
            Serial.println("New Device Added");
          }
          DeviceRssi[i] = ppkt->rx_ctrl.rssi;
          haventPrintedSince++;
          if(PACKAGE_INSIGHT_MODE){ // Device Unknown! Show Insights
            for(int u; u < 100; u++){
              Serial.print(HexToString(ppkt->payload[u]) + " ");
            }
            Serial.println();  
            Serial.print(" Sender: ");
            for(int i = 0; i < 6;i++){
              Serial.print(HexToString(hdr->addr2[i]) + " "); 
            }
            Serial.print(" Target: ");
            for(int i = 0; i < 6;i++){
              Serial.print(HexToString(hdr->addr1[i]) + " "); 
            }
            Serial.println();
          }
          break;
        }
      }
    }
    if(PRINT_BINARY_OCTETTS){
      for(int i; i < 100;i++){
        temp = String(ppkt->payload[i],BIN);
        while(temp.length() < 8){
          temp = "0" + temp;
        }
        Serial.print(temp + " ");  
      }
      Serial.println();
    }

    if(INTERPRETING_PACKAGES){
      int pc = ppkt->payload[0] & 0b00111111;
      String Type = FindType(pc);
      Serial.println(Type);
      if(Type == "Beacon"){ // This horrible Piece exists, becasue the serial Terminal cant display above 32 bits so ... this had to be done ... and it dosent even want to work ... 
        if((ppkt->payload[0] & 0b11000000) == 0b00000000){
          uint64_t TimeStamp = (ppkt->payload[31]) | (ppkt->payload[30] << 1*8) | (ppkt->payload[29] << 2*8) | (ppkt->payload[28] << 3*8) | (ppkt->payload[27] << 4*8) | (ppkt->payload[26] << 5*8) | (ppkt->payload[25] << 6*8) | (ppkt->payload[24] << 7*8);
          uint32_t Minute = (TimeStamp/60000);
          Serial.println("AP Minute Uptime " + String(Minute,DEC));
        }
        Serial.println();
        for(int i; i < 150;i++){
          Serial.print(char(ppkt->payload[i]));
        }
      Serial.println();
      }else{
      Serial.println("wtf is this version ?");   
      }
    }
  }
}

// the setup function runs once when you press reset or power the board
void setup() {
  // initialize digital pin 5 as an output.
  Serial.begin(250000);
  delay(10);
  wifi_sniffer_init();
  pinMode(LED_GPIO_PIN, OUTPUT);
}

void loop() {
  if(haventPrintedSince > UPDATE_EVERY_XX_PACKAGES && MAKE_LISTING){
    printall();
  }  
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
}

void cleanSmall(){
  for(int i=0; i < DeviceAnount; i++){
    if(DeviceSents[i] < 0.5){
    DeviceRssi[i] = 0;
    Devices[i] = "";
    DeviceSents[i] = 0;
    }
    DeviceSents[i] -= DeviceSents[i]/100;
  }
}

void printall(){
  cleanSmall();
  
  int TempSent = 0;
  long maxSent = 0;
  tempDevice = "";
  float TempRSSI = 0;
  
    for(int i=0; i < DeviceAnount; i++){
      Highest = -3; // this works this way fk uf
      maxSent = -100;

      
      for(int x = i; x < DeviceAnount; x++){
        if(abs(DeviceRssi[x]) < abs(maxSent)){
          maxSent = DeviceRssi[x];
          Highest = x;
        }
      }
    if(Highest >= 0){
      TempRSSI = DeviceRssi[i];
      tempDevice = Devices[i];
      TempSent = DeviceSents[i];

      DeviceRssi[i] = DeviceRssi[Highest];
      Devices[i] = Devices[Highest];
      DeviceSents[i] = DeviceSents[Highest];

      DeviceRssi[Highest] = TempRSSI;
      Devices[Highest] = tempDevice;
      DeviceSents[Highest] = TempSent;
    }
  }
  haventPrintedSince = 0;
  Serial.println();
  Serial.println("running since: " + String(micros()/1000000.0));
  for(int i = 0; i < DeviceAnount;i++){
    if(Devices[i] != ""){
      Serial.println("Device " + String(i) + " MAC: " + Devices[i] + " AVG RSSI : " + DeviceRssi[i] + " Activity: " + DeviceSents[i]);    
    }
  } 
}

















// fc  | dura|      DRain      |    source       |       BSS ID    |Seq c|    FFFFFFFFRRRRRRRRRRARAAAAAAAAAAAAMMMMMMMMMMMMMMMMEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE| FCS checksum or something
// 40 00 00 00 ff ff ff ff ff ff a8 6d aa 0d 58 aa ff ff ff ff ff ff 20 00 00 07 44 49 52 45 43 54 2d 01 08 0c 12 18 24 30 48 60 6c dd 6d 00 50 f2 04 10 4a 00 01 10 10 3a 00 01 00 10 08 00 02 11 e8 10 47 00 10 53 14 b8 a7 46 0c 4f 78 b8 5f 34 b0 19 0b 47 03 10 54 00 08 00 01 00 50 f2 00 00 00 10 3c 00 
// 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 
//                                                                         1  2  3  4  5  6  7  8 
//                                                                              TimeStamp!




//50 08 3a 01 da a1 19 3f 98 40 ec 8c 9a 5c 30 7d ec 8c








  
