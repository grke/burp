#ifndef _CMD_H
#define _CMD_H

#include <unistd.h>

/* These things appear at the beginning of each line of communication on the
   network, and in the manifest. */

// This comes before any file type entries.
#define CMD_ATTRIBS	'r'	/* File stat information */

#define CMD_ATTRIBS_SIGS 'R'	/* File stat information preceding sigs */
#define CMD_SIG		'S'	/* Signature of a block */
#define CMD_DATA_REQ	'D'	/* Request for block data */
#define CMD_DATA	'B'	/* Block data */
#define CMD_WRAP_UP	'W'	/* Control packet - client can free blocks up
				   to the given index. */

// File types
#define CMD_FILE	'f'	/* Plain file */
#define CMD_ENC_FILE	'y'	/* Encrypted file */
#define CMD_DIRECTORY	'd'	/* Directory */
#define CMD_SOFT_LINK	'l'	/* Soft link */
#define CMD_HARD_LINK	'L'	/* Hard link */
#define CMD_SPECIAL	's'	/* Fifo, socket, device node... */
#define CMD_METADATA	'm'	/* Extra meta data */
#define CMD_ENC_METADATA 'n'	/* Encrypted extra meta data */
#define CMD_EFS_FILE 	'k'	/* Windows EFS file */

// Commands
#define CMD_GEN		'c'	/* Generic command */
#define CMD_ERROR	'e'	/* Error message */
#define CMD_APPEND	'a'	/* Append to a file */
#define CMD_INTERRUPT	'i'	/* Please interrupt the current data flow */
#define CMD_WARNING	'w'	/* A warning */
#define CMD_END_FILE	'x'	/* End of file transmission - also appears at
				   the end of the manifest and contains
				   size/checksum info. */

/* CMD_FILE_UNCHANGED only used in counting stats on the client, for humans */
#define CMD_FILE_CHANGED 'z'

#define CMD_TIMESTAMP	'b'	/* Backup timestamp (in response to list) */


#define CMD_MANIFEST	'M'	/* Path to a manifest */
#define CMD_FINGERPRINT	'F'	/* Fingerprint part of a signature */


/* These things are for the status server/client */

#define	STATUS_IDLE		'i'
#define	STATUS_RUNNING		'r'
#define	STATUS_CLIENT_CRASHED	'c'
#define	STATUS_SERVER_CRASHED	'C'

#define	STATUS_SCANNING		'1'
#define	STATUS_BACKUP		'2'
#define	STATUS_MERGING		'3'
#define	STATUS_SHUFFLING	'4'
#define	STATUS_LISTING		'7'
#define	STATUS_RESTORING	'8'
#define	STATUS_VERIFYING	'9'
#define	STATUS_DELETING		'0'

#define CMD_TOTAL		'Y'
#define CMD_GRAND_TOTAL		'Z'

#define CMD_BYTES_ESTIMATED	'G'
#define CMD_BYTES		'O'
#define CMD_BYTES_RECV		'P'
#define CMD_BYTES_SENT		'Q'

// Legacy stuff
#define CMD_DATAPTH     't'     /* Path to data on the server */
#define CMD_VSS         'v'     /* Windows VSS metadata */
#define CMD_ENC_VSS     'V'     /* Encrypted Windows VSS metadata */
#define CMD_VSS_T       'u'     /* Windows VSS footer */
#define CMD_ENC_VSS_T   'U'     /* Encrypted Windows VSS footer */


extern void cmd_to_text(char cmd, char *buf, size_t len);
extern void cmd_print_all(void);
extern int cmd_is_filedata(char cmd);
extern int cmd_is_link(char cmd);
extern int cmd_is_endfile(char cmd);

#endif
