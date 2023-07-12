#include <AsyncElegantOTA.h>

AsyncElegantOtaClass AsyncElegantOTA;

void AsyncElegantOtaClass::setID(const char* id){
    _id = id;
}

void AsyncElegantOtaClass::setPage(const uint8_t * page, size_t len){
	_page = page;
	_page_len = len;
}

void AsyncElegantOtaClass::setDigitalSignature(UpdaterHashClass* hash, DigitalSignatureVerifier* verifier)
{
	_hash = hash;
	_verifier = verifier;
	verify = true;
}

void AsyncElegantOtaClass::begin(AsyncWebServer *server, const char* username, const char* password){
    _server = server;
	_page = ELEGANT_HTML;
	_page_len = ELEGANT_HTML_SIZE;

    if(strlen(username) > 0){
        _authRequired = true;
        _username = username;
        _password = password;
    }else{
        _authRequired = false;
        _username = "";
        _password = "";
    }

    _server->on("/update/identity", HTTP_GET, [&](AsyncWebServerRequest *request){
        if(_authRequired){
            if(!request->authenticate(_username.c_str(), _password.c_str())){
                return request->requestAuthentication();
            }
        }
        #if defined(ESP8266)
            request->send(200, "application/json", "{\"id\": \""+_id+"\", \"hardware\": \"ESP8266\"}");
        #elif defined(ESP32)
            request->send(200, "application/json", "{\"id\": \""+_id+"\", \"hardware\": \"ESP32\"}");
        #endif
    });

    _server->on("/update", HTTP_GET, [&](AsyncWebServerRequest *request){
        if(_authRequired){
            if(!request->authenticate(_username.c_str(), _password.c_str())){
                return request->requestAuthentication();
            }
        }
        AsyncWebServerResponse *response = request->beginResponse_P(200, "text/html", _page, _page_len);
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    _server->on("/update", HTTP_POST, [&](AsyncWebServerRequest *request) {
        if(_authRequired){
            if(!request->authenticate(_username.c_str(), _password.c_str())){
                return request->requestAuthentication();
            }
        }
        // the request handler is triggered after the upload has finished... 
        // create the response, add header, and send response
        AsyncWebServerResponse *response = request->beginResponse((Update.hasError())?500:200, "text/plain", (Update.hasError())?"FAIL":"OK");
        response->addHeader("Connection", "close");
        response->addHeader("Access-Control-Allow-Origin", "*");
        request->send(response);
        restart();
    }, [&](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
        //Upload handler chunks in data
        if(_authRequired){
            if(!request->authenticate(_username.c_str(), _password.c_str())){
                return request->requestAuthentication();
            }
        }

        if (!index) {
			if(!verify)
			{
				if(!request->hasParam("MD5", true)) {
					return request->send(400, "text/plain", "MD5 parameter missing");
				} 
			}				
			if(verify)
            {
                _sig_len = 0;
                _hash->begin();
            }
            #if defined(ESP8266)
                int cmd = (filename == "filesystem") ? U_FS : U_FLASH;
                Update.runAsync(true);
                size_t fsSize = ((size_t) &_FS_end - (size_t) &_FS_start);
                uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
                if (!Update.begin((cmd == U_FS)?fsSize:maxSketchSpace, cmd)){ // Start with max available size
            #elif defined(ESP32)
                int cmd = (filename == "filesystem") ? U_SPIFFS : U_FLASH;
                if (!Update.begin(UPDATE_SIZE_UNKNOWN, cmd)) { // Start with max available size
            #endif
                Update.printError(Serial);
                return request->send(400, "text/plain", "OTA could not begin");
            }
			if(!verify)
			{
				if(!Update.setMD5(request->getParam("MD5", true)->value().c_str())) {
					return request->send(400, "text/plain", "MD5 parameter invalid");
				}
			}
			
        }

        // Write chunked data to the free sketch space
        if(len)
		{
			_updateData = data;
			_updateDataLen = len;
			if(verify)
			{
				if (_sig_len < _verifier->getSigLen())
				{
					if (_updateDataLen >= (_verifier->getSigLen() - _sig_len))
					{
						memcpy(&_verifier->signature[_sig_len], data, _verifier->getSigLen() - _sig_len);
						_updateDataLen = _updateDataLen - (_verifier->getSigLen() - _sig_len);
						_updateData = &data[_verifier->getSigLen() - _sig_len];
						_sig_len += (_verifier->getSigLen() - _sig_len);
					}
					else
					{
						memcpy(&_verifier->signature[_sig_len], data, _updateDataLen);
						_sig_len += _updateDataLen;
						_updateDataLen = 0;
						_updateData = NULL;
					} 
				}
			}
			if (_updateDataLen > 0)
			{	
				
				if (Update.write(_updateData, _updateDataLen) != _updateDataLen) {
					Update.printError(Serial);
					return request->send(400, "text/plain", "OTA could not begin213");
				}
				if(verify)
				{
					_hash->add(_updateData, _updateDataLen);
				}
			}	
        }
            
        if (final) 
		{ // if the final flag is set then this is the last frame of data
            
			if(verify)
			{
				bool signature_verification = true;
				_hash->end();
				signature_verification = _verifier->verify(_hash, _verifier->signature, _verifier->getSigLen());
				if (!signature_verification)
				{
					if (!Update.end(true)) 
					{ 
						Update.printError(Serial);
						return request->send(400, "text/plain", "Could not end OTA");
					} 
					else 
					{
						return;
					}
				}
				else
				{
					Update.abort();
					return request->send(500, "text/plain", "Signature Error");
				}
			}
			else if (!Update.end(true)) 
			{ //true to set the size to the current progress
                Update.printError(Serial);
                return request->send(400, "text/plain", "Could not end OTA");
            }
			else{
				return;
			}
		}
    });
}

// deprecated, keeping for backward compatibility
void AsyncElegantOtaClass::loop() {
}

void AsyncElegantOtaClass::restart() {
    yield();
    delay(1000);
    yield();
    ESP.restart();
}

String AsyncElegantOtaClass::getID(){
    String id = "";
    #if defined(ESP8266)
        id = String(ESP.getChipId());
    #elif defined(ESP32)
        id = String((uint32_t)ESP.getEfuseMac(), HEX);
    #endif
    id.toUpperCase();
    return id;
}

