/* Experiment to start the sanitising of conf.c, so that we can eventually do
   things like dumping the current configuration. */

#include <stdio.h>
#include <malloc.h>
#include <inttypes.h>
#include <string.h>

enum conf_type
{
        CT_STRING=0,
        CT_INT,
        CT_FLOAT,
        CT_STRLIST
};

enum conf_opt
{
        CO_CONFFILE=0,
        CO_MODE,
        CO_LOCKFILE,
        CO_LOG_TO_SYSLOG,
        CO_MAX
};

struct conf
{
        enum conf_type conf_type;
        const char *field;
	union
	{
		char *s;
		float f;
		uint64_t i;
		struct strlist *sl;
	};
};

static int set_conf(struct conf *conf, enum conf_opt conf_opt,
	enum conf_type conf_type, const char *field)
{
	conf[conf_opt].conf_type=conf_type;
	conf[conf_opt].field=field;
}

static void init_conf(struct conf *c)
{
	set_conf(c, CO_CONFFILE,	CT_STRING,	"conffile");
	set_conf(c, CO_MODE,		CT_INT,		"mode");
	set_conf(c, CO_LOCKFILE,	CT_STRING,	"lockfile");
	set_conf(c, CO_LOG_TO_SYSLOG,	CT_INT,		"log_to_syslog");
}

static void set_int(struct conf *conf, int i)
{
	conf->i=i;
}

static char *get_string(struct conf *conf)
{
	return conf->s;
}

static int get_int(struct conf *conf)
{
	return conf->i;
}

static float get_float(struct conf *conf)
{
	return conf->f;
}

static char *set_string(struct conf *conf, const char *s)
{
	if(conf->s) free(conf->s);
	conf->s=strdup(s);
	return conf->s;
}

static char *conf_data_to_str(struct conf *conf)
{
	static char ret[256]="";
	*ret='\0';
	switch(conf->conf_type)
	{
		case CT_STRING:
			return get_string(conf);
		case CT_FLOAT:
			snprintf(ret, sizeof(ret), "%g", get_float(conf));
			break;
		case CT_INT:
			snprintf(ret, sizeof(ret), "%d", get_int(conf));
			break;
		case CT_STRLIST:
			break;
	}
	return ret;
	
}

static int dump_conf(struct conf *conf)
{
	int i=0;
	for(i=0; i<CO_MAX; i++)
	{
		printf("%s: %s\n", conf[i].field, conf_data_to_str(&conf[i]));
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct conf *conf=NULL;
	conf=calloc(1, sizeof(struct conf)*CO_MAX);
	init_conf(conf);
	set_int(&conf[CO_MODE], 10);
	set_string(&conf[CO_LOCKFILE], "adffsd");
	set_string(&conf[CO_LOCKFILE], "kljdf");

	dump_conf(conf);
	free(conf);
	return 0;
}
