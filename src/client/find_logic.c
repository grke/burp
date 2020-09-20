#include "../burp.h"
#include "../alloc.h"
#include "../handy.h"
#include "../conf.h"
#include "../conffile.h"
#include "../regexp.h"
#include "../strlist.h"
#include "../log.h"
#include "find.h"
#include "find_logic.h"

#include <uthash.h>

#ifdef HAVE_LINUX_OS
#include <sys/statfs.h>
#endif
#ifdef HAVE_SUN_OS
#include <sys/statvfs.h>
#endif

typedef struct _node node;
typedef struct _dllist dllist;
typedef int TOKENS;

// define our tokens as 'flags' to ease the parsing
#define EVAL_FALSE   0  // The evaluated function returned FALSE
#define EVAL_TRUE    1  // The evaluated function returned TRUE
#define LEFT_PARENS  2  // (
#define RIGHT_PARENS 3  // )
#define AND_FUNC     4  // and
#define OR_FUNC      5  // or
#define NOT          6  // not
#define GTE          7  // >=
#define GT           8  // >
#define LTE          9  // <=
#define LT           10 // <
#define EQ           11 // =
#define PLACEHOLDER  99 // placeholder value

// a node contains a TOKEN with a reference to its successor and ancestor
struct _node
{
	TOKENS val;

	node *next;
	node *prev;
};

// our expression will be converted in a doubly-linked list of nodes to ease
// its evaluation
struct _dllist
{
	node *head;
	node *tail;
	size_t len;
};

// the first parsing will split the string expression in string tokens
// ie. 'file_size>10Kb and (file_ext=pst or file_ext=ost)' =>
// {"file_size>10Kb", "and", "(", "file_ext=pst", "or", "file_ext=ost", ")"}
struct tokens
{
	char **list;
	size_t size;
	int valid;
};

// an expression is a hash record to retrieve already parsed records
struct expression
{
	char *id;
	struct tokens *tokens;
	UT_hash_handle hh;
};

// a cregex is a pre-compiled regex
struct cregex
{
	char *id;
	regex_t *compiled;
	UT_hash_handle hh;
};

// these are some caches
struct expression *cache=NULL;
struct cregex *regex_cache=NULL;

static void free_tokens(struct tokens *ptr)
{
	if(!ptr) return;
	free_list_w(&ptr->list, ptr->size);
	free_v((void **)&ptr);
}

static void free_expression(struct expression *ptr)
{
	if(!ptr) return;
	free_tokens(ptr->tokens);
	free_v((void **)&ptr);
}

static void free_cregex(struct cregex *ptr)
{
	if(!ptr) return;
	regex_free(&(ptr->compiled));
	free_v((void **)&ptr);
}

static void free_node(node **ptr)
{
	if(!*ptr) return;
	free_v((void **)ptr);
}

// append a node to a given list
static void list_append(dllist **list, node *data)
{
	dllist *l=*list;
	if(!l || !data) return;
	if(!l->tail)
	{
		l->head=data;
		l->tail=data;
		data->prev=NULL;
		data->next=NULL;
	}
	else
	{
		l->tail->next=data;
		data->prev=l->tail;
		l->tail=data;
		data->next=NULL;
	}
	l->len++;
}

// retrieve a node by its position in the list
static node *list_get_node_by_id(dllist *list, int id)
{
	node *ret=NULL;
	int cpt=0;
	if(!list || id<0 || id>(int)list->len) return ret;
	ret=list->head;
	for(cpt=0, ret=list->head; ret && cpt<id; cpt++, ret=ret->next);
	if(cpt<id) return NULL;  // id out of range
	return ret;
}

// empty list
static void list_reset(dllist **list)
{
	node *tmp;
	dllist *l=*list;
	if(!l || l->len==0) return;
	tmp=l->tail;
	while(tmp)
	{
		node *buf=tmp->prev;
		l->tail=buf;
		if(l->tail)
			l->tail->next=NULL;
		l->len--;
		tmp->prev=NULL;
		free_node(&tmp);
		tmp=buf;
	}
}

static dllist *new_list(void)
{
	dllist *ret;
	if(!(ret=(dllist *)malloc_w(sizeof(*ret), __func__))) return NULL;
	ret->len=0;
	ret->head=NULL;
	ret->tail=NULL;
	return ret;
}

static node *new_node(int value)
{
	node *ret;
	if(!(ret=(node *)malloc_w(sizeof(*ret), __func__))) return NULL;
	ret->val=value;
	ret->next=NULL;
	ret->prev=NULL;
	return ret;
}

// here we actually convert our expression into a list of string tokens
static struct tokens *create_token_list(char *expr)
{
	char *n=NULL;
	char *n2=NULL;
	char **toks=NULL;
	size_t nb_elements=0;
	struct tokens *ret=NULL;
	int opened, closed;

	if(!(n=charreplace_noescaped_w(expr, '(', " ( ", &opened, __func__))) goto end;
	if(!(n2=charreplace_noescaped_w(n, ')', " ) ", &closed, __func__))) goto end;
	if(!(toks=charsplit_noescaped_w(n2, ' ', &nb_elements, __func__))) goto end;
	if(!(ret=(struct tokens *)malloc_w(sizeof(*ret), __func__))) goto end;

	ret->list=toks;
	ret->size=nb_elements;
	ret->valid=(opened==closed);
end:
	free_w(&n);
	free_w(&n2);
	return ret;
}

// we create our "expression" record to be cached
static struct expression *parse_expression(char *expr)
{
	struct expression *ret=NULL;
	struct tokens *toks;
	if(!(toks=create_token_list(expr))) return ret;
	if(!(ret=(struct expression *)malloc_w(sizeof(*ret), __func__))) goto error;
	ret->tokens=toks;
	ret->id=expr;
	return ret;
error:
	free_tokens(toks);
	return ret;
}

// search for the positions of the 'what' token in our tokens list
static void find(dllist *toks, TOKENS what, int start, dllist **positions)
{
	int i;
	node *tmp;
	for(i=0, tmp=toks->head; i<(int)toks->len; i++, tmp=tmp->next)
	{
		if(i<start) continue;  // skip the unwanted positions
		if(tmp && tmp->val==what) list_append(positions, new_node(i));
	}
}

// search for parentheses and return their positions
// always return the deepest parentheses first
// example:
//       false or ( false or ( true or false ) )
// 1 =>                      ^               ^   (true, 5, 9)
// 2 =>           ^                            ^ (true, 2, 10)
static void parens(dllist *toks, int *has, int *left, int *right)
{
	dllist *positions;
	if(!(positions=new_list()))
	{
		*has=0;
		*left=-1;
		*right=-1;
		return;
	}
	find(toks, LEFT_PARENS, 0, &positions);
	if(positions->len==0)
	{
		*has=0;
		*left=-1;
		*right=-1;
		goto end;
	}
	*left=positions->tail->val;
	list_reset(&positions);
	find(toks, RIGHT_PARENS, *left+4, &positions);
	if(positions->len==0)
	{
		// special case (token) instead of ( token or/and token )
		list_reset(&positions);
		find(toks, RIGHT_PARENS, *left+1, &positions);
	}
	*right=positions->head->val;
	*has=1;
end:
	list_reset(&positions);
	free_v((void **)&positions);
}

// utility function
static char *strip_quotes(char *src)
{
	int len;
	char *strip=NULL;
	if(!(len=strlen(src))) goto end;
	if((*src=='\'' || *src=='"') && *src==src[len-1]) // strip the quotes
	{
		if(!(strip=(char *)malloc_w(len-1, __func__))) goto end;
		strip=strncpy(strip, src+1, len-2);
		strip[len-2]='\0';
	}
end:
	return strip;
}

// function 'file_ext'
static int eval_file_ext(char *tok, const char *fname)
{
	const char *cp;
	int len;
	char *strip=NULL;
	if(!(len=strlen(tok))) goto end;
	for(; *tok=='='; ++tok);
	if(!(len=strlen(tok))) goto end;  // test again after we trimmed the '='
	strip=strip_quotes(tok);
	for(cp=fname+strlen(fname)-1; cp>=fname; cp--)
	{
		if(*cp!='.') continue;
		if((strip && !strcasecmp(strip, cp+1))
		   || (!strip && !strcasecmp(tok, cp+1)))
			return EVAL_TRUE;
	}
end:
	free_w(&strip);
	return EVAL_FALSE;
}

// function 'path_match'
static int eval_path_match(char *tok, const char *fname)
{
	int ret=EVAL_FALSE;
	struct cregex *reg;
	char *strip=NULL;
	if(strlen(tok)==0) goto end;
	for(; *tok=='='; ++tok);
	if(strlen(tok)==0) goto end;  // test again after we trimmed the '='
	if(regex_cache)
		HASH_FIND_STR(regex_cache, tok, reg);
	else
		reg=NULL;
	if(!reg)
	{
		regex_t *tmp;
		if((strip=strip_quotes(tok)))
			tmp=regex_compile_backup(strip);
		else
			tmp=regex_compile_backup(tok);
		if(!(reg=(struct cregex *)malloc_w(sizeof(*reg), __func__)))
		{
			regex_free(&tmp);
			goto end;
		}
		reg->id=strdup_w(tok, __func__);
		reg->compiled=tmp;
		HASH_ADD_KEYPTR(hh, regex_cache, reg->id, strlen(reg->id), reg);
	}
	if(regex_check(reg->compiled, fname))
		ret=EVAL_TRUE;
end:
	free_w(&strip);
	return ret;
}

// function 'file_match'
static int eval_file_match(char *tok, const char *fname)
{
	int len=strlen(fname);
	for(; len>0 && fname[len-1]!='/'; len--);
	return eval_path_match(tok, fname+len);
}

// function 'file_size'
static int eval_file_size(char *tok, uint64_t filesize)
{
	int ret=EVAL_FALSE;
	char *strip=NULL;
	TOKENS eval=PLACEHOLDER;
	uint64_t s=0;
	if(strlen(tok)==0) goto end;
	for(; ; tok++)
	{
		if(*tok!='>' && *tok!='<' && *tok!='=') break;
		switch(*tok)
		{
			case '<':
				eval=LT;
				break;
			case '>':
				eval=GT;
				break;
			case '=':
				switch(eval)
				{
					case LT:
						eval=LTE;
						break;
					case GT:
						eval=GTE;
						break;
					case PLACEHOLDER:
					case EQ:
						eval=EQ;
						break;
					default:
						eval=EVAL_FALSE;
				}
				break;
		}
	}
	if((strip=strip_quotes(tok)))
		get_file_size(strip, &s, NULL, -1);
	else
		get_file_size(tok, &s, NULL, -1);
	switch(eval)
	{
		case LT:
			ret=filesize<s;
			break;
		case LTE:
			ret=filesize<=s;
			break;
		case GT:
			ret=filesize>s;
			break;
		case GTE:
			ret=filesize>=s;
			break;
		case EQ:
			ret=filesize==s;
			break;
		default:
			ret=EVAL_FALSE;
	}
end:
	free_w(&strip);
	return ret;
}

// search what function to use
static int eval_func(char *tok, const char *filename, uint64_t filesize)
{
	int ret;
	if(!strncmp(tok, "file_ext", 8))
		ret=eval_file_ext(tok+8, filename);
	else if(!strncmp(tok, "file_match", 10))
		ret=eval_file_match(tok+10, filename);
	else if(!strncmp(tok, "path_match", 10))
		ret=eval_path_match(tok+10, filename);
	else if(!strncmp(tok, "file_size", 9))
		ret=eval_file_size(tok+9, filesize);
	else
		ret=EVAL_FALSE;
	return ret;
}

// convert a string token into a TOKENS
static node *str_to_node(char *tok, const char *filename, uint64_t filesize)
{
	int ret;
	if(!strncmp(tok, "and", 3))
		ret=AND_FUNC;
	else if(!strncmp(tok, "or", 2))
		ret=OR_FUNC;
	else if(!strncmp(tok, "(", 1))
		ret=LEFT_PARENS;
	else if(!strncmp(tok, ")", 1))
		ret=RIGHT_PARENS;
	else if(!strncmp(tok, "not", 3))
		ret=NOT;
	else
		ret=eval_func(tok, filename, filesize);
	return new_node(ret);
}

// evaluate a trio of tokens like 'true or false'
static int eval_triplet(node *head, int def)
{
	TOKENS left, func, right;
	left=head->val;
	func=head->next->val;
	right=head->next->next->val;
	switch(func)
	{
		case AND_FUNC:
			return left && right;
		case OR_FUNC:
			return left || right;
		default:
			return def;
	}
}

// factorise tokens by recursively evaluating them
static int bool_eval(dllist **tokens, int def)
{
	dllist *toks=*tokens;
	if(toks->len==1)
		return toks->head->val;
	else if(toks->len==2)
	{
		switch(toks->head->val)
		{
			case NOT:
				return !toks->tail->val;
			default:
				return toks->tail->val;
		}
	}
	/* here we search for 'not' tokens */
	if(toks->len>3)
	{
		dllist *new_tokens;
		node *tmp;
		int negate=0, is_negation=0;
		for(tmp=toks->head; tmp; tmp=tmp->next)
		{
			if(tmp->val==NOT)
			{
				is_negation=1;
				break;
			}
		}
		if(is_negation)
		{
			if(!(new_tokens=new_list())) return 0;
			for(tmp=toks->head; tmp; tmp=tmp->next)
			{
				if(tmp->val==NOT)
					negate=!negate;
				else
				{
					if(negate)
					{
						list_append(&new_tokens, new_node(!(tmp->val)));
						negate=0;
					}
					else
					{
						list_append(&new_tokens, new_node(tmp->val));
					}
				}
			}
			list_reset(tokens);
			free_v((void **)tokens);
			*tokens=new_tokens;
			toks=*tokens;
		}
	}
	/* here we don't have any negations anymore, but we may have chains of
	 * expressions to evaluate recursively */
	if(toks->len>3)
	{
		node *tmp;
		dllist *new_tokens;
		int i;
		tmp=new_node(eval_triplet(toks->head, def));
		if(!(new_tokens=new_list()))
		{
			free_node(&tmp);
			return 0;
		}
		list_append(&new_tokens, tmp);
		for(tmp=toks->head, i=0; tmp; tmp=tmp->next, i++)
		{
			if(i<3) continue;
			list_append(&new_tokens, new_node(tmp->val));
		}
		list_reset(tokens);
		free_v((void **)tokens);
		*tokens=new_tokens;
		toks=*tokens;
		return bool_eval(tokens, def);
	}
	if(toks->len%3!=0) return def;
	return eval_triplet(toks->head, def);
}

// evaluate our list of tokens
static int eval_parsed_expression(dllist **tokens, int def)
{
	dllist *toks=*tokens, *sub;
	node *begin, *end, *tmp;
	int has, left, right, count;
	if(!toks || toks->len==0) return def;
	if(toks->len==1) return toks->head->val;
	parens(toks, &has, &left, &right);
	// we don't have parentheses, we can evaluate the tokens
	if(!has)
		return bool_eval(tokens, def);
	// we have parentheses
	// we retrieve the two nodes '(' and ')'
	begin=list_get_node_by_id(toks, left);
	end=list_get_node_by_id(toks, right);
	// then we capture only the tokens surrounded by the parentheses
	if(!(sub=new_list())) return def;
	tmp=begin->next;
	count=0;
	while(tmp && count<right-left-1)
	{
		list_append(&sub, new_node(tmp->val));
		tmp=tmp->next;
		count++;
	}
	count++;
	// evaluate the inner expression
	tmp=new_node(bool_eval(&sub, def));
	// we replace all the tokens parentheses included with the new computed node
	// first element of the list
	if(!begin->prev)
		(*tokens)->head=tmp;
	else if (!end->next)  // last element of the list
		(*tokens)->tail=tmp;
	toks->len-=count;  // decrement our list size
	tmp->prev=begin->prev;
	tmp->next=end->next;
	if(begin->prev)
		begin->prev->next=tmp;
	else if(end->next)
		end->next->prev=tmp;
	// cleanup "orphans" nodes
	tmp=begin;
	while(tmp && count>=0)
	{
		if(tmp)
		{
			node *buf=tmp->next;
			free_node(&tmp);
			tmp=buf;
			count--;
		}
	}
	list_reset(&sub);
	free_v((void **)&sub);
	return eval_parsed_expression(tokens, def);
}

static int eval_expression(char *expr, const char *filename, uint64_t filesize, int def)
{
	int ret=def, i;
	struct expression *parsed;
	dllist *tokens=NULL;
	if(cache)
		HASH_FIND_STR(cache, expr, parsed);
	else
		parsed=NULL;
	if(!parsed)
	{
		if(!(parsed=parse_expression(expr))) return def;
		HASH_ADD_KEYPTR(hh, cache, parsed->id, strlen(parsed->id), parsed);
	}
	if(!parsed || !parsed->tokens->valid) goto end;
	if(!(tokens=new_list())) goto end;
	for(i=0; i<(int)parsed->tokens->size; i++)
		list_append(&tokens, str_to_node(parsed->tokens->list[i], filename, filesize));
	ret=eval_parsed_expression(&tokens, def);
end:
	list_reset(&tokens);
	free_v((void **)&tokens);
	return ret;
}

// cleanup our caches
void free_logic_cache(void)
{
	struct expression *parsed, *tmp;
	struct cregex *reg, *tmp2;
	if(cache)
	{
		HASH_ITER(hh, cache, parsed, tmp)
		{
			HASH_DEL(cache, parsed);
			free_expression(parsed);
		}
	}
	if(regex_cache)
	{
		HASH_ITER(hh, regex_cache, reg, tmp2)
		{
			HASH_DEL(regex_cache, reg);
			free_w(&(reg->id));
			free_cregex(reg);
		}
	}
}

/* return 1 if there is a match, 'def' is there isn't any match, and 'miss' if
 * there are no rules to eval */
static int is_logic(struct strlist *list, struct FF_PKT *ff, int miss, int def)
{
	if(!list) return miss;
	if(!S_ISREG(ff->statp.st_mode)) return def;  // ignore directories
	for(; list; list=list->next)
		if(eval_expression(list->path, ff->fname, (uint64_t)ff->statp.st_size, miss))
			return 1;
	return def;
}

int is_logic_excluded(struct conf **confs, struct FF_PKT *ff)
{
	return is_logic(get_strlist(confs[OPT_EXCLOGIC]), ff, /* missing */ 0, /* default */ 0);
}

int is_logic_included(struct conf **confs, struct FF_PKT *ff)
{
	return is_logic(get_strlist(confs[OPT_INCLOGIC]), ff, /* missing */ 1, /* default */ 0);
}
