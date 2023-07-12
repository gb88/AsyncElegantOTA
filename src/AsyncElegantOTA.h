#ifndef AsyncElegantOTA_h
#define AsyncElegantOTA_h

#warning AsyncElegantOTA.loop(); is deprecated, please remove it from loop() if defined. This function will be removed in a future release.

#include "Arduino.h"
#include "stdlib_noniso.h"

#if defined(ESP8266)
    #include "ESP8266WiFi.h"
    #include "ESPAsyncTCP.h"
    #include "flash_hal.h"
    #include "FS.h"
#elif defined(ESP32)
    #include "WiFi.h"
    #include "AsyncTCP.h"
    #include "Update.h"
    #include "esp_int_wdt.h"
    #include "esp_task_wdt.h"
#endif

#include "Hash.h"
#include "ESPAsyncWebServer.h"
#include "FS.h"

#include "elegantWebpage.h"
#include "DigitalSignatureVerifier.h"

class AsyncElegantOtaClass{

    public:
        void
            setID(const char* id),
			setPage(const uint8_t * page, size_t len),
            begin(AsyncWebServer *server, const char* username = "", const char* password = ""),
            loop(),
			setDigitalSignature(UpdaterHashClass* hash, DigitalSignatureVerifier* verifier),
            restart();

    private:
        AsyncWebServer *_server;

        String getID();

        String _id = getID();
        String _username = "";
        String _password = "";
        bool _authRequired = false;
		uint8_t * _updateData;
		size_t _updateDataLen;
		size_t _sig_len;
		uint8_t * signature;
		bool verify;
		size_t _page_len;
		const uint8_t * _page;
		UpdaterHashClass* _hash;
		DigitalSignatureVerifier* _verifier; 
};

extern AsyncElegantOtaClass AsyncElegantOTA;

#endif
