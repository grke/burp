#ifndef _CMD_H
#define _CMD_H

#include <unistd.h>

enum cmd
{
/* These things appear at the beginning of each line of communication on the
   network, and in the manifest. */

// This comes before any file type entries.
	CMD_ATTRIBS='r',	/* File stat information */

// File types
	CMD_FILE	='f',	/* Plain file */
	CMD_ENC_FILE	='y',	/* Encrypted file */
	CMD_DIRECTORY	='d',	/* Directory */
	CMD_SOFT_LINK	='l',	/* Soft link */
	CMD_HARD_LINK	='L',	/* Hard link */
	CMD_SPECIAL	='s',	/* Fifo, socket, device node... */
	CMD_METADATA	='m',	/* Extra meta data */
	CMD_ENC_METADATA='n',	/* Encrypted extra meta data */
	CMD_EFS_FILE 	='k',	/* Windows EFS file */
	CMD_DATAPTH	='t',	/* Path to data on the server */
	CMD_VSS		='v',	/* Windows VSS metadata */
	CMD_ENC_VSS	='V',	/* Encrypted Windows VSS metadata */
	CMD_VSS_T	='u',	/* Windows VSS footer */
	CMD_ENC_VSS_T	='U',	/* Encrypted Windows VSS footer */

// Commands
	CMD_GEN		='c',	/* Generic command */
	CMD_ERROR	='e',	/* Error message */
	CMD_APPEND	='a',	/* Append to a file */
	CMD_INTERRUPT	='i',	/* Please interrupt the current data flow */
	CMD_MESSAGE	='p',	/* A message */
	CMD_WARNING	='w',	/* A warning */
	CMD_END_FILE	='x',	/* End of file transmission - also appears at
				   the end of the manifest and contains
				   size/checksum info. */

// CMD_FILE_UNCHANGED only used in counting stats on the client, for humans
	CMD_FILE_CHANGED='z',

	CMD_TIMESTAMP	='b',	/* Backup timestamp (in response to list) */


	CMD_MANIFEST	='M',	/* Path to a manifest */
	CMD_SAVE_PATH   ='q',   /* Save path part of a signature */


// These things are for the status server/client

	CMD_TOTAL	='Y',
	CMD_GRAND_TOTAL	='Z',

	CMD_BYTES_ESTIMATED='G',
	CMD_BYTES	='O',
	CMD_BYTES_RECV	='P',
	CMD_BYTES_SENT	='Q',
	CMD_TIMESTAMP_END='E',
};


extern void cmd_print_all(void);
extern char *cmd_to_text(enum cmd cmd);
extern int cmd_is_filedata(enum cmd cmd);
extern int cmd_is_vssdata(enum cmd cmd);
extern int cmd_is_link(enum cmd cmd);
extern int cmd_is_endfile(enum cmd cmd);
extern int cmd_is_encrypted(enum cmd cmd);
extern int cmd_is_metadata(enum cmd cmd);
extern int cmd_is_estimatable(enum cmd cmd);

#endif
