#include "burp.h"
#include "yajl_gen_w.h"

yajl_gen yajl=NULL;

int yajl_map_open_w(void)
{
	return yajl_gen_map_open(yajl)!=yajl_gen_status_ok;
}

int yajl_map_close_w(void)
{
	return yajl_gen_map_close(yajl)!=yajl_gen_status_ok;
}

int yajl_array_open_w(void)
{
	return yajl_gen_array_open(yajl)!=yajl_gen_status_ok;
}

int yajl_array_close_w(void)
{
	return yajl_gen_array_close(yajl)!=yajl_gen_status_ok;
}

int yajl_gen_str_w(const char *str)
{
	return yajl_gen_string(yajl,
		(const unsigned char *)str, strlen(str))!=yajl_gen_status_ok;
}

int yajl_gen_int_w(long long num)
{
	return yajl_gen_integer(yajl, num)!=yajl_gen_status_ok;
}

int yajl_gen_str_pair_w(const char *field, const char *value)
{
	if(yajl_gen_str_w(field) || yajl_gen_str_w(value))
		return -1;
	return 0;
}

int yajl_gen_int_pair_w(const char *field, long long value)
{
	if(yajl_gen_str_w(field) || yajl_gen_int_w(value))
		return -1;
	return 0;
}
