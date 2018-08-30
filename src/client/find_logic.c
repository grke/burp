#include "../burp.h"
#include "../alloc.h"
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

// empty expression always return 'true'
int empty_res=EVAL_TRUE;

static void free_tokens(struct tokens *ptr)
{
	if(!ptr) return;
	free_list_w(ptr->list, (int)ptr->size);
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
	free_p(*ptr);
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
	if(!list || id<0 || id>list->len) return ret;
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
	if(!(ret=malloc_w(sizeof(*ret), __func__))) return NULL;
	ret->len=0;
	ret->head=NULL;
	ret->tail=NULL;
	return ret;
}

static node *new_node(int value)
{
	node *ret;
	if(!(ret=malloc_w(sizeof(*ret), __func__))) return NULL;
	ret->val=value;
	ret->next=NULL;
	ret->prev=NULL;
	return ret;
}

// here we actually convert our expression into a list of string tokens
static struct tokens *create_token_list(char *expr)
{
	char *new=NULL, *new2=NULL;
	char **toks=NULL;
	size_t nb_elements=0;
	struct tokens *ret=NULL;
	if(!(new=strreplace_w(expr, "(", " ( ", __func__))) goto end;
	if(!(new2=strreplace_w(new, ")", " ) ", __func__))) goto end;
	if(!(toks=strsplit_w(new2, " ", &nb_elements, __func__))) goto end;
	if(!(ret=malloc_w(sizeof(*ret), __func__))) goto end;
	ret->list=toks;
	ret->size=nb_elements;
end:
	free_w(&new);
	free_w(&new2);
	return ret;
}

// we create our "expression" record to be cached
static struct expression *parse_expression(char *expr)
{
	struct expression *ret=NULL;
	struct tokens *toks;
	if(!(toks=create_token_list(expr))) return ret;
	if(!(ret=malloc_w(sizeof(*ret), __func__))) goto error;
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
	for(i=0, tmp=toks->head; i<toks->len; i++, tmp=tmp->next)
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

// function 'file_ext'
static int eval_file_ext(char *tok, const char *fname)
{
	const char *cp;
	if(strlen(tok)==0) goto end;
	for(; *tok=='='; ++tok);
	if(strlen(tok)==0) goto end;  // test again after we trimmed the '='
	for(cp=fname+strlen(fname)-1; cp>=fname; cp--)
	{
		if(*cp!='.') continue;
		if(!strcasecmp(tok, cp+1))
			return EVAL_TRUE;
	}
end:
	return EVAL_FALSE;
}

// function 'file_match'
static int eval_file_match(char *tok, const char *fname)
{
	struct cregex *reg;
	if(strlen(tok)==0) goto end;
	for(; *tok=='='; ++tok);
	if(strlen(tok)==0) goto end;  // test again after we trimmed the '='
	if(regex_cache)
		HASH_FIND_STR(regex_cache, tok, reg);
	else
		reg=NULL;
	if(!reg)
	{
		regex_t *tmp=regex_compile(tok);
		if(!(reg=malloc_w(sizeof(*reg), __func__)))
		{
			regex_free(&tmp);
			goto end;
		}
		reg->id=strdup_w(tok, __func__);
		reg->compiled=tmp;
		HASH_ADD_KEYPTR(hh, regex_cache, reg->id, strlen(reg->id), reg);
	}
	if(regex_check(reg->compiled, fname))
		return EVAL_TRUE;
end:
	return EVAL_FALSE;
}

// function 'file_size'
static int eval_file_size(char *tok, uint64_t filesize)
{
	int ret=EVAL_FALSE;
	TOKENS eval=EVAL_FALSE;
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
				}
				break;
		}
	}
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
		default:
			ret=EVAL_FALSE;
	}
end:
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
	else if(!strncmp(tok, "file_size", 9))
		ret=eval_file_size(tok+9, filesize);
	else
		ret=EVAL_FALSE;
	return ret;
}

// convert a string token into a TOKENS
static node *eval_token(char *tok, const char *filename, uint64_t filesize)
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
static int eval_tokens(node *head)
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
			return 0;
	}
}

// factorise tokens by recursively evaluating them
static int bool_eval(dllist **tokens)
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
		tmp=new_node(eval_tokens(toks->head));
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
		return bool_eval(tokens);
	}
	if(toks)
		return eval_tokens(toks->head);
	return 0;
}

// evaluate our list of tokens
static int eval_parsed_expression(dllist **tokens, int def)
{
	dllist *toks=*tokens, *sub;
	node *begin, *end, *tmp;
	int has, left, right, count, forward=1;
	if(!toks || toks->len==0) return def;
	if(toks->len==1) return toks->head->val;
	parens(toks, &has, &left, &right);
	// we don't have parentheses, we can evaluate the tokens
	if(!has)
		return bool_eval(tokens);
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
	tmp=new_node(bool_eval(&sub));
	// we replace all the tokens parentheses included with the new computed node
	// first element of the list
	if(!begin->prev)
	{
		forward=0;
		toks->head=tmp;
	}
	else if (!end->next)  // last element of the list
		toks->tail=tmp;
	toks->len-=count;  // decrement our list size
	tmp->prev=begin->prev;
	tmp->next=end->next;
	if(begin->prev)
		begin->prev->next=tmp;
	// cleanup "forgotten" nodes
	if(forward)
		tmp=begin;
	else
		tmp=end;
	while(tmp && count>=0)
	{
		if(tmp)
		{
			node *buf;
			if(forward)
				buf=tmp->next;
			else
				buf=tmp->prev;
			free_node(&tmp);
			tmp=buf;
			count--;
		}
	}
	list_reset(&sub);
	free_v((void **)&sub);
	return eval_parsed_expression(tokens, def);
}

static int eval_expression(char *expr, const char *filename, uint64_t filesize)
{
	int ret=0, i;
	struct expression *parsed;
	dllist *tokens;
	if(cache)
		HASH_FIND_STR(cache, expr, parsed);
	else
		parsed=NULL;
	if(!parsed)
	{
		if(!(parsed=parse_expression(expr))) return 0;
		HASH_ADD_KEYPTR(hh, cache, parsed->id, strlen(parsed->id), parsed);
	}
	if(!(tokens=new_list())) goto end;
	for(i=0; i<parsed->tokens->size; i++)
		list_append(&tokens, eval_token(parsed->tokens->list[i], filename, filesize));
	ret=eval_parsed_expression(&tokens, empty_res);
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
		if(eval_expression(list->path, ff->fname, (uint64_t)ff->statp.st_size))
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
