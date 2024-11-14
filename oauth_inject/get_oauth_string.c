#include <stdio.h>
#include <string.h>

struct sp_s {
	char spacer[0x38];
        char* auth_password;
        char* refresh_token;
};

static char OAUTH_STRING[] = 
	"client_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&"
	"client_secret=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&"
	"refresh_token=%s&"
	"grant_type=refresh_token";

void get_oauth_string(char* str, struct sp_s* sp) {
	char* format;
	char* input;
	char* msg;
	if (!sp->auth_password || sp->auth_password[0] == 0) {
		msg = "No AuthPassword. refresh_token = X_GApiRefreshToken\n";
		format = OAUTH_STRING;
		input = sp->refresh_token;
	} else if (strncmp(sp->auth_password, OAUTH_STRING, 10) == 0) {
		msg = "client_id in AuthPassword. Using as complete oauth request\n";
		format = "%s";
		input = sp->auth_password;
	} else {
		msg = "Short AuthPassword. refresh_token = AuthPassword\n";
		format = OAUTH_STRING;
		input = sp->auth_password;
	}
	syslog(7, msg);
	sprintf(str, format, input);
	//syslog(7, "OAUTH REQUEST STRING: %s", str);
}
