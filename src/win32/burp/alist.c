/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2003-2010 Free Software Foundation Europe e.V.

   The main author of Bacula is Kern Sibbald, with contributions from
   many others, a complete list can be found in the file AUTHORS.
   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   Bacula® is a registered trademark of Kern Sibbald.
   The licensor of Bacula is the Free Software Foundation Europe
   (FSFE), Fiduciary Program, Sumatrastrasse 25, 8006 Zürich,
   Switzerland, email:ftf@fsfeurope.org.
*/
/*
 *  Bacula array list routines
 *
 *    alist is a simple malloc'ed array of pointers.  For the moment,
 *      it simply malloc's a bigger array controlled by num_grow.
 *      Default is to realloc the pointer array for each new member.
 *
 *   Kern Sibbald, June MMIII
 *
 */
/*
 * This file comes from bacula-5.0.3:src/lib/alist.c
 *  Graham Keeling, 2014
 */

#include "burp.h"
#include "alist.h"

/* Private grow list function. Used to insure that at least one more "slot" is
   available. */
// FIX THIS: stupid bacula stuff - malloc/realloc can fail and the program
// will continue and maybe segfault.
void alist::grow_list()
{
	if(!items)
	{
		if(!num_grow) num_grow=1;
		items=(void **)malloc(num_grow*sizeof(void *));
		max_items=num_grow;
	}
	else if(num_items==max_items)
	{
		max_items+=num_grow;
		items=(void **)realloc(items, max_items*sizeof(void *));
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
