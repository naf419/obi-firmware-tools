// arm-unknown-linux-gnueabi-gcc led.c -o led

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>


struct LED_ARGS
{
	char ledno;
	char color0;
	char color1;
	char _padding;
	int times;
	int interval;
};

enum LED_REQUEST
{
	LED_SET = 1,
	LED_CLEAR = 2,
	LED_BLINK = 4
};

enum LED_COLOR
{
	LED_OFF = 0,
	LED_GREEN = 1,
	LED_RED = 3
};


int usage() {
	printf("USAGE:\nled <RED|GREEN|OFF> <RED|GREEN|OFF> <interval>\n\n");
}


int main(int argc, char** argv)
{
	struct LED_ARGS args;
	args.ledno = 0; //power
	args.times = 65535;

	if (argc != 4) {
		usage();
		return 1;
	}

	if (!strcmp(argv[1],"RED")) args.color0 = LED_RED;
	else if (!strcmp(argv[1],"GREEN")) args.color0 = LED_GREEN;
	else if (!strcmp(argv[1],"OFF")) args.color0 = LED_OFF;
	else { usage(); return 1; }

	if (!strcmp(argv[2],"RED")) args.color1 = LED_RED;
	else if (!strcmp(argv[2],"GREEN")) args.color1 = LED_GREEN;
	else if (!strcmp(argv[2],"OFF")) args.color1 = LED_OFF;
	else { usage(); return 1; }

	args.interval = atoi(argv[3]);

	int fd = open("/dev/led", O_RDWR);
	ioctl(fd, LED_BLINK, &args);
	close(fd);

	return 0;
}
