#include "burp.h"
#include "alist.h"

/*
 * Private grow list function. Used to insure that
 *   at least one more "slot" is available.
 */
void alist::grow_list()
{
   if (items == NULL) {
      if (num_grow == 0) {
         num_grow = 1;                /* default if not initialized */
      }
      items = (void **)malloc(num_grow * sizeof(void *));
      max_items = num_grow;
   } else if (num_items == max_items) {
      max_items += num_grow;
      items = (void **)realloc(items, max_items * sizeof(void *));
   }
}

void *alist::first()
{
   cur_item = 1;
   if (num_items == 0) {
      return NULL;
   } else {
      return items[0];
   }
}

void *alist::last()
{
   if (num_items == 0) {
      return NULL;
   } else {
      cur_item = num_items;
      return items[num_items-1];
   }
}

void *alist::next()
{
   if (cur_item >= num_items) {
      return NULL;
   } else {
      return items[cur_item++];
   }
}

void *alist::prev()
{
   if (cur_item <= 1) {
      return NULL;
   } else {
      return items[--cur_item];
   }
}

/*
 * prepend an item to the list -- i.e. add to beginning
 */
void alist::prepend(void *item) {
   grow_list();
   if (num_items == 0) {
      items[num_items++] = item;
      return;
   }
   for (int i=num_items; i > 0; i--) {
      items[i] = items[i-1];
   }
   items[0] = item;
   num_items++;
}


/*
 * Append an item to the list
 */
void alist::append(void *item) {
   grow_list();
   items[num_items++] = item;
}

/* Remove an item from the list */
void * alist::remove(int index)
{
   void *item;
   if (index < 0 || index >= num_items) {
      return NULL;
   }
   item = items[index];
   num_items--;
   for (int i=index; i < num_items; i++) {
      items[i] = items[i+1];
   }
   return item;
}


/* Get the index item -- we should probably allow real indexing here */
void * alist::get(int index)
{
   if (index < 0 || index >= num_items) {
      return NULL;
   }
   return items[index];
}

/* Destroy the list and its contents */
void alist::destroy()
{
   if (items) {
      if (own_items) {
         for (int i=0; i<num_items; i++) {
            free(items[i]);
            items[i] = NULL;
         }
      }
      free(items);
      items = NULL;
   }
}
