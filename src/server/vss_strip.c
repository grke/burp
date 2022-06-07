#include "../burp.h"

static const char *prog=NULL;

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static void dump_sid(struct bsid *sid)
{
	printf("VSS header: %d %d %" PRId64 " %d\n",
        	sid->dwStreamId,
        	sid->dwStreamAttributes,
        	sid->Size,
        	sid->dwStreamNameSize);
}

static int skip_data(FILE *inp, size_t s)
{
	size_t got=0;
	char buf[4096]="";
	while((got=fread(buf, 1, min(sizeof(buf), s), inp))>0)
	{
		s-=got;
		if(s<=0) break;
	}
	if(s!=0)
	{
		fprintf(stderr, "Error - expected %lu more bytes\n",
			(unsigned long)s);
		return -1;
	}
	return 0;
}

static int open_fp(const char *path, FILE **fp, const char *mode, FILE *def)
{
	if(path)
	{
		if(!(*fp=fopen(path, mode)))
		{
			fprintf(stderr, "could not open %s: %s\n",
				path, strerror(errno));
			return 1;
		}
	}
	else *fp=def;
	return 0;
}

static int ensure_read(struct bsid *sid, FILE *inp)
{
	size_t got=0;
	size_t offset=0;
	while((got=fread(sid+offset, 1, bsidsize-offset, inp))>0)
	{
		offset+=got;
		if(offset>=bsidsize) return 0;
	}
	if(offset!=bsidsize) return -1;
	return 0;
}

static int dump_headers(FILE *inp)
{
        struct bsid sid;
	while(!ensure_read(&sid, inp))
        {
		size_t s=0;
		dump_sid(&sid);
		//if(sid.dwStreamId==1) break;
		s=(sid.Size)+(sid.dwStreamNameSize);
		if(skip_data(inp, s)) return -1;
	}
	return 0;
}

static int ensure_write(char *buf, size_t got, FILE *outp)
{
	size_t wrote=0;
	while((wrote=fwrite(buf, 1, got, outp))>0)
	{
		got-=wrote;
		if(got<=0) return 0;
	}
	fprintf(stderr, "Error in write: %s\n", strerror(errno));
	return -1;
}

static int extract_data(FILE *inp, FILE *outp, size_t s)
{
	size_t got=0;
	char buf[4096]="";
	while((got=fread(buf, 1, min(sizeof(buf), s), inp))>0)
	{
		if(ensure_write(buf, got, outp))
			return -1;
		s-=got;
		if(s<=0) break;
	}
	if(s!=0)
	{
		fprintf(stderr, "Error - expected %lu more bytes\n",
			(unsigned long)s);
		return -1;
	}
	return 0;
}

static int main_work(FILE *inp, FILE *outp)
{
        struct bsid sid;
	while(!ensure_read(&sid, inp))
        {
		size_t s=0;
		s=(sid.Size)+(sid.dwStreamNameSize);
		if(sid.dwStreamId==1)
		{
			if(extract_data(inp, outp, s)) return 1;
			break;
		}
		else
		{
			if(skip_data(inp, s)) return -1;
		}
	}
	return 0;
}

static void usage(void)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, " Options:\n");
	fprintf(stderr, " -i path     Input file\n");
	fprintf(stderr, "             If -i is not given, input will be read on stdin\n");
	fprintf(stderr, " -o path     Output file\n");
	fprintf(stderr, "             If -o is not given, output will be written on stdout\n");
	fprintf(stderr, " -p          Print VSS header info\n");
	fprintf(stderr, " -h|-?       Print this message\n");
}

static void get_progname(const char *arg)
{
	if((prog=strrchr(arg, '/'))) prog++;
	else prog=arg;
}

int main(int argc, char *argv[])
{
	int r=0;
	int dump=0;
	int option=0;
	FILE *inp=NULL;
	const char *in=NULL;
	const char *out=NULL;

	get_progname(argv[0]);

	while((option=getopt(argc, argv, "i:ho:p?"))!=-1)
	{
		switch(option)
		{
			case 'i':
				in=optarg;
				break;
			case 'o':
				out=optarg;
				break;
			case 'p':
				dump=1;
				break;
			case 'h':
			case '?':
			default:
				usage();
				return 1;
		}
	}

	if(open_fp(in, &inp, "rb", stdin)) return 1;

	if(dump)
	{
		r=dump_headers(inp);
	}
	else
	{
		FILE *outp=NULL;
		if(open_fp(out, &outp, "wb", stdout))
		{
			fclose(inp);
			return 1;
		}
		r=main_work(inp, outp);
		if(outp) fclose(outp);
	}
	if(inp) fclose(inp);
	if(r) return 1;
	return 0;
}
