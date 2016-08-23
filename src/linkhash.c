/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2000-2010 Free Software Foundation Europe e.V.

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
   Code extracted from findlib from bacula-5.0.3, and
   heavily modified. Therefore, I have retained the bacula copyright notice.
   
      Graham Keeling, 2015.
*/

#include "burp.h"
#include "handy.h"
#include "linkhash.h"

// List of all hard linked files found.
struct f_link **linkhash=NULL;

#define LINK_HASHTABLE_BITS 16
#define LINK_HASHTABLE_SIZE (1<<LINK_HASHTABLE_BITS)
#define LINK_HASHTABLE_MASK (LINK_HASHTABLE_SIZE-1)

int linkhash_init(void)
{
	if(!(linkhash=(struct f_link **)calloc_w(1,
		LINK_HASHTABLE_SIZE*sizeof(*linkhash), __func__)))
			return -1;
	return 0;
}

void linkhash_free(void)
{
	int i;
	struct f_link *lp;
	struct f_link *lc;

	if(!linkhash) return;

	for(i=0; i<LINK_HASHTABLE_SIZE; i++)
	{
		// Free up list of hard linked files.
		lp=linkhash[i];
		while(lp)
		{
			lc=lp;
			lp=lp->next;
			if(lc)
			{
				free_w(&lc->name);
				free_v((void **)&lc);
			}
		}
		linkhash[i]=NULL;
	}
	free_v((void **)&linkhash);
}

static inline int get_hash(struct stat *statp)
{
	int hash=statp->st_dev;
	uint64_t i=statp->st_ino;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	i >>= 16;
	hash ^= i;
	return hash & LINK_HASHTABLE_MASK;
}

struct f_link *linkhash_search(struct stat *statp, struct f_link ***bucket)
{
	struct f_link *lp;
	*bucket=&linkhash[get_hash(statp)];
	for(lp=**bucket; lp; lp=lp->next)
		if(lp->ino==(ino_t)statp->st_ino
		  && lp->dev==(dev_t)statp->st_dev)
			return lp;
	return NULL;
}

int linkhash_add(char *fname, struct stat *statp, struct f_link **bucket)
{
	struct f_link *new_fl;
	if(!(new_fl=(struct f_link *)malloc_w(sizeof(struct f_link), __func__))
	  || !(new_fl->name=strdup_w(fname, __func__)))
		return -1;
	new_fl->ino=statp->st_ino;
	new_fl->dev=statp->st_dev;
	new_fl->next=*bucket;
	*bucket=new_fl;
	return 0;
}
