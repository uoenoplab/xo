#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util.h"

void print_mac_address(unsigned char *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void hexdump(const char *title, void *buf, size_t len)
{
	printf("%s (%lu bytes) :\n", title, len);
	for (size_t i = 0; i < len; i++) {
		printf("%02hhX ", ((unsigned char *)buf)[i]);
		if (i % 16 == 15) printf("\n");
	}
	printf("\n");
}


double elapsed_time(struct timespec a, struct timespec b)
{
	double elapsed = (double)(a.tv_sec - b.tv_sec) + (double)(a.tv_nsec - b.tv_nsec) / (double)1e9;
	return elapsed;
}

void get_datetime_str(char *buf, size_t length)
{
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(buf, length, "%a, %d %b %Y %H:%M:%S %Z", &tm);
}

void convertToISODateTime(const char* inputDateTime, char* outputISODateTime) {
	struct tm timeinfo;
	memset(&timeinfo, 0, sizeof(struct tm));

	// Define the format of the input date string
	const char* inputFormat = "%a, %d %b %Y %H:%M:%S %Z";

	// Parse the input date string
	if (strptime(inputDateTime, inputFormat, &timeinfo) == NULL) {
		fprintf(stderr, "Error parsing date string.\n");
		return;
	}

	// Convert the parsed time to time_t
	time_t epochTime = mktime(&timeinfo);

	// Format the time in ISO format
	strftime(outputISODateTime, 128, "%Y-%m-%dT%H:%M:%SZ", gmtime(&epochTime));
}

void unescapeHtml(char* str) {
	char* input = str;
	char* output = str;

	while (*input) {
		if (strncmp(input, "&amp;", 5) == 0) {
			*output = '&';
			input += 5;
		} else if (strncmp(input, "&lt;", 4) == 0) {
			*output = '<';
			input += 4;
		} else if (strncmp(input, "&gt;", 4) == 0) {
			*output = '>';
			input += 4;
		} else if (strncmp(input, "&quot;", 6) == 0) {
			*output = '"';
			input += 6;
		} else if (strncmp(input, "&apos;", 6) == 0) {
			*output = '\'';
			input += 6;
		} else if (strncmp(input, "%28", 3) == 0) {
			*output = '(';
			input += 4;
		} else if (strncmp(input, "%29", 3) == 0) {
			*output = ')';
			input += 4;
		} else {
			*output = *input;
			input++;
		}
		output++;
	}
	*output = '\0'; // Null-terminate the output string.
}
