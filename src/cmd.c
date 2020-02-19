#include "burp.h"
#include "cmd.h"

char *cmd_to_text(enum cmd cmd)
{
	static char buf[256];
	size_t len=sizeof(buf);
	*buf='\0';
	switch(cmd)
	{
		case CMD_ATTRIBS:
			snprintf(buf, len, "File attribute information"); break;
		case CMD_ATTRIBS_SIGS:
			snprintf(buf, len, "File attribute information preceding block signatures"); break;
		case CMD_SIG:
			snprintf(buf, len, "Block signature"); break;
		case CMD_DATA_REQ:
			snprintf(buf, len, "Request for block of data"); break;
		case CMD_DATA:
			snprintf(buf, len, "Block data"); break;
		case CMD_WRAP_UP:
			snprintf(buf, len, "Control packet"); break;
		case CMD_FILE:
			snprintf(buf, len, "Plain file"); break;
		case CMD_ENC_FILE:
			snprintf(buf, len, "Encrypted file"); break;
		case CMD_DIRECTORY:
			snprintf(buf, len, "Directory"); break;
		case CMD_SOFT_LINK:
			snprintf(buf, len, "Soft link"); break;
		case CMD_HARD_LINK:
			snprintf(buf, len, "Hard link"); break;
		case CMD_SPECIAL:
			snprintf(buf, len, "Special file - fifo, socket, device node"); break;
		case CMD_METADATA:
			snprintf(buf, len, "Extra meta data"); break;
		case CMD_GEN:
			snprintf(buf, len, "Generic command"); break;
		case CMD_ERROR:
			snprintf(buf, len, "Error message"); break;
		case CMD_APPEND:
			snprintf(buf, len, "Append to a file"); break;
		case CMD_INTERRUPT:
			snprintf(buf, len, "Interrupt"); break;
		case CMD_MESSAGE:
			snprintf(buf, len, "Message"); break;
		case CMD_WARNING:
			snprintf(buf, len, "Warning"); break;
		case CMD_END_FILE:
			snprintf(buf, len, "End of file transmission"); break;
		case CMD_ENC_METADATA:
			snprintf(buf, len, "Encrypted meta data"); break;
		case CMD_EFS_FILE:
			snprintf(buf, len, "Windows EFS file"); break;
		case CMD_FILE_CHANGED:
			snprintf(buf, len, "Plain file changed"); break;
		case CMD_TIMESTAMP:
			snprintf(buf, len, "Backup timestamp"); break;
		case CMD_TIMESTAMP_END:
			snprintf(buf, len, "Timestamp now/end"); break;
		case CMD_MANIFEST:
			snprintf(buf, len, "Path to a manifest"); break;
		case CMD_FINGERPRINT:
			snprintf(buf, len, "Fingerprint part of a signature"); break;
		case CMD_SAVE_PATH:
			snprintf(buf, len, "Save path part of a signature"); break;

		// For the status server/client */

		case CMD_TOTAL:
			snprintf(buf, len, "Total counter"); break;
		case CMD_GRAND_TOTAL:
			snprintf(buf, len, "Grand total counter"); break;
		case CMD_BYTES_ESTIMATED:
			snprintf(buf, len, "Bytes estimated"); break;
		case CMD_BYTES:
			snprintf(buf, len, "Bytes"); break;
		case CMD_BYTES_RECV:
			snprintf(buf, len, "Bytes received"); break;
		case CMD_BYTES_SENT:
			snprintf(buf, len, "Bytes sent"); break;

		// Protocol1 only.
		case CMD_DATAPTH:
			snprintf(buf, len, "Path to data on the server"); break;
		case CMD_VSS:
			snprintf(buf, len, "Windows VSS header"); break;
		case CMD_ENC_VSS:
			snprintf(buf, len, "Encrypted windows VSS header"); break;
		case CMD_VSS_T:
			snprintf(buf, len, "Windows VSS footer"); break;
		case CMD_ENC_VSS_T:
			snprintf(buf, len, "Encrypted windows VSS footer"); break;

		// No default so that we get compiler warnings when we forget
		// to add new ones here.
	}
	if(!*buf) snprintf(buf, len, "----------------");
	return buf;
}

void cmd_print_all(void)
{
	int i=0;
	char cmds[256]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	printf("\nIndex of symbols\n\n");
	for(i=0; cmds[i]; i++)
		printf("  %c: %s\n", cmds[i], cmd_to_text((enum cmd)cmds[i]));
	printf("\n");
}

int cmd_is_filedata(enum cmd cmd)
{
	return     cmd==CMD_FILE
		|| cmd==CMD_ENC_FILE
		|| cmd==CMD_METADATA
		|| cmd==CMD_ENC_METADATA
		|| cmd==CMD_EFS_FILE;
}

int cmd_is_vssdata(enum cmd cmd)
{
	return     cmd==CMD_VSS
		|| cmd==CMD_ENC_VSS
		|| cmd==CMD_VSS_T
		|| cmd==CMD_ENC_VSS_T;
}

int cmd_is_link(enum cmd cmd)
{
	return cmd==CMD_SOFT_LINK || cmd==CMD_HARD_LINK;
}

int cmd_is_endfile(enum cmd cmd)
{
	return cmd==CMD_END_FILE;
}

int cmd_is_encrypted(enum cmd cmd)
{
	return     cmd==CMD_ENC_FILE
		|| cmd==CMD_ENC_METADATA
		|| cmd==CMD_ENC_VSS
		|| cmd==CMD_ENC_VSS_T
		|| cmd==CMD_EFS_FILE;
}

int cmd_is_metadata(enum cmd cmd)
{
	return cmd_is_vssdata(cmd)
		|| cmd==CMD_METADATA
		|| cmd==CMD_ENC_METADATA;
}

int cmd_is_estimatable(enum cmd cmd)
{
	return     cmd==CMD_FILE
		|| cmd==CMD_ENC_FILE
		|| cmd==CMD_EFS_FILE;
}
