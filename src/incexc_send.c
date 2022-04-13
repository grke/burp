#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "cmd.h"
#include "log.h"
#include "prepend.h"
#include "strlist.h"
#include "incexc_send.h"

static int send_incexc_string(struct asfd *asfd,
	const char *field, const char *str)
{
	char *tosend=NULL;
	int ret=-1;
	if(!str) return 0;
	if(!(tosend=prepend_n(field, str, strlen(str), " = ")))
		goto end;
	if(asfd->write_str(asfd, CMD_GEN, tosend))
	{
		logp("Error in async_write_str when sending incexc\n");
		goto end;
	}
	ret=0;
end:
	free_w(&tosend);
	return ret;
}

static int send_incexc_str(struct asfd *asfd, struct conf *conf)
{
	return send_incexc_string(asfd, conf->field, get_string(conf));
}

static int send_incexc_uint(struct asfd *asfd, struct conf *conf)
{
	char tmp[64]="";
	snprintf(tmp, sizeof(tmp), "%d", get_int(conf));
	return send_incexc_string(asfd, conf->field, tmp);
}

static int send_incexc_uint64(struct asfd *asfd, struct conf *conf)
{
	char tmp[32]="";
	snprintf(tmp, sizeof(tmp), "%" PRIu64, get_uint64_t(conf));
	return send_incexc_string(asfd, conf->field, tmp);
}

static int send_incexc_strlist(struct asfd *asfd, struct conf *conf)
{
	struct strlist *l;
	for(l=get_strlist(conf); l; l=l->next)
		if(send_incexc_string(asfd, conf->field, l->path)) return -1;
	return 0;
}

static int do_sends(struct asfd *asfd, struct conf **confs, int flag)
{
	int i=0;
	int r=-1;
	for(i=0; i<OPT_MAX; i++)
	{
		if(!(confs[i]->flags & flag)) continue;
		switch(confs[i]->conf_type)
		{
			case CT_STRING:
				if(send_incexc_str(asfd, confs[i]))
					goto end;
				break;
			case CT_STRLIST:
				if(send_incexc_strlist(asfd, confs[i]))
					goto end;
				break;
			case CT_UINT:
				if(send_incexc_uint(asfd, confs[i]))
					goto end;
				break;
			case CT_SSIZE_T:
				if(send_incexc_uint64(asfd, confs[i]))
					goto end;
				break;
			case CT_FLOAT:
			case CT_MODE_T:
			case CT_E_BURP_MODE:
			case CT_E_RECOVERY_METHOD:
			case CT_E_RSHASH:
			case CT_CNTR:
				break;
		}
	}
	r=0;
end:
	return r;
}

static int do_request_response(struct asfd *asfd,
	const char *reqstr, const char *repstr)
{
	return (asfd->write_str(asfd, CMD_GEN, reqstr)
	  || asfd_read_expect(asfd, CMD_GEN, repstr));
}

int incexc_send_client(struct asfd *asfd, struct conf **confs)
{
	if(do_request_response(asfd, "incexc", "incexc ok")
	  || do_sends(asfd, confs, CONF_FLAG_INCEXC)
	  || do_request_response(asfd, "incexc end", "incexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server(struct asfd *asfd, struct conf **confs)
{
	/* 'sincexc' and 'sincexc ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends(asfd, confs, CONF_FLAG_INCEXC)
	  || do_request_response(asfd, "sincexc end", "sincexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server_restore(struct asfd *asfd, struct conf **confs)
{
	/* 'srestore' and 'srestore ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends(asfd, confs, CONF_FLAG_INCEXC_RESTORE)
	  || do_request_response(asfd, "srestore end", "srestore end ok"))
		return -1;
	return 0;
}
