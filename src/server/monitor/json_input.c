#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

// Input from asfd is going to be line buffered. Just keep it very simple
// minded for now, and pretty much ignore most of the JSON formatting -
// assume all {} and [] are on separate lines.

#define NAME_LINE	"   \"name\": \""
#define STATUS_LINE	"   \"status\": \""

static int parse(const char *buf)
{
	char *cp;
	static char *name=NULL;
	static char *status=NULL;
	if(!strncmp(buf, NAME_LINE, strlen(NAME_LINE)))
	{
		if((cp=strrchr(buf, '"'))) *cp='\0';
		name=strdup(buf+strlen(NAME_LINE));
	}
	else if(!strncmp(buf, STATUS_LINE, strlen(STATUS_LINE)))
	{
		if((cp=strrchr(buf, '"'))) *cp='\0';
		status=strdup(buf+strlen(STATUS_LINE));
	}

	if(name && status)
	{
		printf("name: %s\n", name);
		printf("status: %s\n", status);
		if(name) free(name); name=NULL;
		if(status) free(status); status=NULL;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp=NULL;
	char buf[512]="";
	char *cp=NULL;
	if(argc<2)
	{
		fprintf(stderr, "Need an arg\n");
		return 1;
	}
	if(!(fp=fopen(argv[1], "rb")))
	{
		fprintf(stderr, "Could not open %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}
	while(fgets(buf, sizeof(buf), fp))
	{
		if((cp=strrchr(buf, '\n'))) *cp='\0';
		parse(buf);
	}
	fclose(fp);
	return 0;
}
