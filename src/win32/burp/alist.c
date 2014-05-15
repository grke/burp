#include "burp.h"
#include "alist.h"

/* Private grow list function. Used to insure that at least one more "slot" is
   available. */
// FIX THIS: malloc/realloc can fail and the program will continue and maybe
// segfault.
void alist::grow_list()
{
	if(!items)
	{
		if(!num_grow) num_grow=1;
		items=(void **)
			malloc_w(num_grow*sizeof(void *), __func__);
		max_items=num_grow;
	}
	else if(num_items==max_items)
	{
		max_items+=num_grow;
		items=(void **)
			realloc_w(items, max_items*sizeof(void *), __func__);
	}
}

void *alist::first()
{
	cur_item=1;
	if(!num_items) return NULL;
	return items[0];
}

void *alist::last()
{
	if(!num_items) return NULL;
	cur_item = num_items;
	return items[num_items-1];
}

void *alist::next()
{
	if(cur_item>=num_items) return NULL;
	return items[cur_item++];
}

void *alist::prev()
{
	if(cur_item<=1) return NULL;
	return items[--cur_item];
}

void alist::prepend(void *item)
{
	grow_list();
	if(!num_items)
	{
		items[num_items++]=item;
		return;
	}
	for(int i=num_items; i>0; i--) items[i]=items[i-1];
	items[0]=item;
	num_items++;
}


void alist::append(void *item)
{
	grow_list();
	items[num_items++]=item;
}

void *alist::remove(int index)
{
	void *item;
	if(index<0 || index>=num_items) return NULL;
	item=items[index];
	num_items--;
	for(int i=index; i<num_items; i++) items[i]=items[i+1];
	return item;
}


// Get the index item -- we should probably allow real indexing here.
void *alist::get(int index)
{
	if(index<0 || index>=num_items) return NULL;
	return items[index];
}

void alist::destroy()
{
	if(!items) return;
	if(own_items) for(int i=0; i<num_items; i++)
	{
		free(items[i]);
		items[i]=NULL;
	}
	free(items);
	items=NULL;
}
