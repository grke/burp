#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

#define LOG_MANIFEST	0x0001
#define LOG_MANIFEST_GZ	0x0002
#define LOG_BACKUP	0x0004
#define LOG_BACKUP_GZ	0x0008
#define LOG_VERIFY	0x0010
#define LOG_VERIFY_GZ	0x0020
#define LOG_RESTORE	0x0040
#define LOG_RESTORE_GZ	0x0080

extern int json_start(struct asfd *asfd);
extern int json_end(struct asfd *asfd);
extern int json_send_summary(struct asfd *asfd, struct cstat *cstat);
extern int json_send_backup_list(struct asfd *asfd,
	struct cstat *clist, struct cstat *cstat);
extern int json_send_backup_dir_files(struct asfd *asfd,
	struct bu *bu, uint16_t flags);

#endif
