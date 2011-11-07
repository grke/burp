#ifndef _CMD_H
#define _CMD_H

// used in CMD_*:
// a
// c
// d
// e
// E
// f
// g
// G
// h
// H
// i
// j
// J
// l
// L
// m
// M
// n
// p
// P
// r
// s
// t
// u
// w
// x
// X
// y
// Y
// z
// Z

/* These things appear at the beginning of each line of communication on the
   network, and in the manifest. */

// These two come before any file type entries
#define CMD_DATAPTH	't'	/* Path to data on the server */
#define CMD_STAT	'r'	/* File stat information */

// File types
#define CMD_FILE	'f'	/* Plain file */
#define CMD_ENC_FILE	'y'	/* Encrypted file */
#define CMD_DIRECTORY	'd'	/* Directory */
#define CMD_SOFT_LINK	'l'	/* Soft link */
#define CMD_HARD_LINK	'L'	/* Hard link */
#define CMD_SPECIAL	's'	/* Fifo, socket, device node... */
#define CMD_METADATA	'm'	/* Extra meta data */
#define CMD_ENC_METADATA 'n'	/* Encrypted extra meta data */

// Commands
#define CMD_GEN		'c'	/* Generic command */
#define CMD_ERROR	'e'	/* Error message */
#define CMD_APPEND	'a'	/* Append to a file */
#define CMD_INTERRUPT	'i'	/* Please interrupt the current data flow */
#define CMD_WARNING	'w'	/* A warning */
#define CMD_END_FILE	'x'	/* End of file transmission - also appears at
				   the end of the manifest and contains
				   size/checksum info. */

/* Stuff only used in counting stats, for humans */
#define CMD_FILE_CHANGED		'z'
#define CMD_FILE_SAME			'u'

#define CMD_METADATA_CHANGED		'p'
#define CMD_METADATA_SAME		'M'

#define CMD_ENC_METADATA_CHANGED	'P'
#define CMD_ENC_METADATA_SAME		'E'

#define CMD_ENC_FILE_CHANGED		'Z'
#define CMD_ENC_FILE_SAME		'Y'

#define CMD_DIRECTORY_CHANGED		'D'
#define CMD_DIRECTORY_SAME		'X'

#define CMD_HARD_LINK_CHANGED		'j'
#define CMD_HARD_LINK_SAME		'J'

#define CMD_SOFT_LINK_CHANGED		'g'
#define CMD_SOFT_LINK_SAME		'G'

#define CMD_SPECIAL_CHANGED		'h'
#define CMD_SPECIAL_SAME		'H'

#define CMD_TIMESTAMP	'b'	/* Backup timestamp (in response to list) */




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
#define	STATUS_DEDUP		'd'

#endif // _CMD_H
