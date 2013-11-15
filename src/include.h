#ifndef _SRC_INCLUDES_H
#define _SRC_INCLUDES_H

// There is probably somewhere better to put these.
enum action
{
	ACTION_BACKUP=0,
	ACTION_RESTORE,
	ACTION_VERIFY,
	ACTION_LIST,
	ACTION_LONG_LIST,
	ACTION_BACKUP_TIMED,
	ACTION_STATUS,
	ACTION_STATUS_SNAPSHOT,
	ACTION_ESTIMATE,
	ACTION_DELETE,
};

#include "asyncio.h"
#include "attribs.h"
#include "base64.h"
#include "berrno.h"
#include "bfile.h"
#include "blk.h"
#include "burpconfig.h"
#include "burp.h"
#include "cmd.h"
#include "conf.h"
#include "counter.h"
#include "forkchild.h"
#include "handy.h"
#include "incexc_recv.h"
#include "incexc_send.h"
#include "include.h"
#include "iobuf.h"
#include "lock.h"
#include "log.h"
#include "msg.h"
#include "prepend.h"
#include "regexp.h"
#include "sbuf.h"
#include "ssl.h"
#include "strlist.h"
#include "version.h"

#endif
