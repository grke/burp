#include "burp.h"
#include "prog.h"

void reset_filecounter(struct cntr *c)
{
	c->totalcounter=0;
	c->filecounter=0;
	c->changedcounter=0;
	c->unchangedcounter=0;
	c->newcounter=0;
	c->directorycounter=0;
	c->specialcounter=0;
	c->hardlinkcounter=0;
	c->softlinkcounter=0;
	c->warningcounter=0;
	c->bytecounter=0;
	c->recvbytecounter=0;
	c->sentbytecounter=0;
	c->encryptedcounter=0;
}

static const char *bytes_to_human(unsigned long long counter)
{
	static char ret[32]="";
	float div=(float)counter;
	char units[3]="";

	if(div<1024) return "";

	if((div/=1024)<1024)
		snprintf(units, sizeof(units), "KB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "MB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "GB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "TB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "EB");
	else
	{
		div/=1024;
		snprintf(units, sizeof(units), "PB");
	}
	snprintf(ret, sizeof(ret), " (%.2f %s)", div, units);
	//strcat(ret, units);
	//strcat(ret, ")");
	return ret;
}

static void pcounter(const char *str, unsigned long long counter)
{
	if(counter) logp(str, counter);
}

static void bcounter(const char *str, unsigned long long counter)
{
	if(counter)
	{
		char msg[128]="";
		snprintf(msg, sizeof(msg),
			str, counter, bytes_to_human(counter));
		logp("%s", msg);
	}
}

void end_filecounter(struct cntr *c, int print, enum action act)
{
	if(print) printf(" %llu\n\n", c->totalcounter);

	if(act==ACTION_RESTORE)
	{
		logp("Restored files:            %llu\n", c->filecounter);
		pcounter("Restored encrypted files:  %llu\n", c->encryptedcounter);
	}
	else if(act==ACTION_VERIFY)
	{
		logp("Verified files:            %llu\n", c->filecounter);
		pcounter("Verified encrypted files:  %llu\n", c->encryptedcounter);
	}
	else
	{
		pcounter("Files:                     %llu\n", c->filecounter);
		pcounter("Encrypted files:           %llu\n", c->encryptedcounter);
		pcounter("New files:                 %llu\n", c->newcounter);
		pcounter("Changed files:             %llu\n", c->changedcounter);
		pcounter("Unchanged files:           %llu\n", c->unchangedcounter);
	}
	pcounter("Directories:               %llu\n", c->directorycounter);
	pcounter("Soft links:                %llu\n", c->softlinkcounter);
	pcounter("Hard links:                %llu\n", c->hardlinkcounter);
	pcounter("Special files:             %llu\n", c->specialcounter);
	//logp("\n");
	pcounter("Total:                     %llu\n", c->totalcounter);
	//logp("\n");
	pcounter("Warnings:                  %llu\n", c->warningcounter);
	bcounter("Bytes received:  %llu%s\n", c->recvbytecounter);
	bcounter("Bytes sent:      %llu%s\n", c->sentbytecounter);
	bcounter("Bytes in backup: %llu%s\n", c->bytecounter);
	//logp("\n");
	reset_filecounter(c);
}

void do_filecounter(struct cntr *c, char ch, int print)
{
	if(print)
	{
		if(!c->totalcounter && !c->warningcounter) printf("\n");
		printf("%c", ch);
	}
	switch(ch)
	{
		case 'f': ++(c->filecounter); break;
		case 'x': ++(c->changedcounter); break;
		case 'F': ++(c->newcounter); break;
		case 'd': ++(c->directorycounter); break;
		case 's': ++(c->specialcounter); break;
		case 'l': ++(c->softlinkcounter); break;
		case 'L': ++(c->hardlinkcounter); break;
		case 'w': ++(c->warningcounter); return; // do not add to total
		case 'y': ++(c->encryptedcounter); break;
	}
	if(!((++(c->totalcounter))%64) && print)
		printf(" %llu\n", c->totalcounter);
	fflush(stdout);
}

void do_filecounter_bytes(struct cntr *c, unsigned long long bytes)
{
	c->bytecounter+=bytes;
}

void do_filecounter_sentbytes(struct cntr *c, unsigned long long bytes)
{
	c->sentbytecounter+=bytes;
}

void do_filecounter_recvbytes(struct cntr *c, unsigned long long bytes)
{
	c->recvbytecounter+=bytes;
}
