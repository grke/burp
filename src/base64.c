/*
   Bacula® - The Network Backup Solution

   Copyright (C) 2000-2007 Free Software Foundation Europe e.V.

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
 *   Generic base 64 input and output routines
 *
 *    Written by Kern E. Sibbald, March MM.
 */
/*
 * Originally from bacula-5.0.3:src/lib/base64.c, with minor formatting
 * changes.
 *    Graham Keeling, 2014.
 */

#include "burp.h"
#include "base64.h"

static uint8_t const base64_digits[64]=
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static uint8_t base64_map[128];

/* Initialize the Base 64 conversion routines */
void base64_init(void)
{
	int i;
	memset(base64_map, 0, sizeof(base64_map));
	for(i=0; i<64; i++)
		base64_map[(uint8_t)base64_digits[i]]=i;
}

/*
 * Convert a value to base64 characters. The result is stored in where, which
 * must be at least 13 bytes long.
 *
 * Returns the number of characters stored (not including the EOS).
 */
int to_base64(int64_t value, char *where)
{
	uint64_t val;
	int i=0;
	int n;

	/* Handle negative values */
	if(value<0)
	{
		where[i++]='-';
		value=-value;
	}

	/* Determine output size */
	val=value;
	do
	{
		val>>=6;
		i++;
	} while(val);
	n=i;

	/* Output characters */
	val=value;
	where[i]=0;
	do
	{
		where[--i]=base64_digits[val & (uint64_t)0x3F];
		val>>=6;
	} while(val);
	return n;
}

/*
 * Convert the Base 64 characters in where to a value.
 *
 * Returns the number of characters converted.
 */
int from_base64(int64_t *value, const char *where)
{
	uint64_t val=0;
	int i=0;
	int neg=0;

	if(where[i]==' ')
		i++;

	/* Check if it is negative */
	if(where[i]=='-')
	{
		i++;
		neg=1;
	}
	/* Construct value */
	for(char c=where[i]; c && c!=' '; c=where[++i])
	{
		if(!isalnum((unsigned char)c) && c!='+' && c!='/')
			continue;
		val<<=6;
		val+=base64_map[(uint8_t)c];
	}

	*value=neg?-(int64_t)val:(int64_t)val;
	return i;
}

uint64_t base64_to_uint64(const char *buf)
{
	int64_t val=0;
	from_base64(&val, buf);
	return (uint64_t)val;
}

void base64_from_uint64(uint64_t src, char *buf)
{
	char *p=buf;
	p+=to_base64(src, p);
	*p=0;
}
