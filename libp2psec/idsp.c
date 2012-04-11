/***************************************************************************
 *   Copyright (C) 2012 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/


#ifndef F_IDSP_C
#define F_IDSP_C


#include <stdlib.h>


struct s_idsp {
	int *idfwd;
	int *idlist;
	int count;
	int used;
	int iter;
};


static void idspReset(struct s_idsp *idsp) {
	int i;
	for(i=0; i<idsp->count; i++) {
		idsp->idfwd[i] = -1;
		idsp->idlist[i] = i;
	}
	idsp->used = 0;
	idsp->iter = 0;
}


static int idspCreate(struct s_idsp *idsp, const int size) {
	int *idfwd_mem = NULL;
	int *idlist_mem = NULL;
	if(size > 0) {
		idfwd_mem = malloc(sizeof(int) * size);
		if(idfwd_mem != NULL) {
			idlist_mem = malloc(sizeof(int) * size);
			if(idlist_mem != NULL) {
				idsp->idfwd = idfwd_mem;
				idsp->idlist = idlist_mem;
				idsp->count = size;
				idspReset(idsp);
				return 1;
			}
			free(idfwd_mem);
		}
	}
	return 0;
}


static int idspNext(struct s_idsp *idsp) {
	int iter = idsp->iter;
	int used = idsp->used;
	if(used > 0) {
		if(!(iter < used)) iter = 0;
		idsp->iter = (iter + 1);
		return idsp->idlist[iter];
	}
	else {
		return -1;
	}
}


static int idspNew(struct s_idsp *idsp) {
	int new_id;
	int new_pos;
	if(idsp->used < idsp->count) {
		new_pos = idsp->used++;
		new_id = idsp->idlist[new_pos];
		idsp->idfwd[new_id] = new_pos;
		return new_id;
	}
	else {
		return -1;
	}
}


static int idspGetPos(struct s_idsp *idsp, const int id) {
	if((id >= 0) && (id < idsp->count)) {
		return idsp->idfwd[id];
	}
	else {
		return -1;
	}
}


static void idspDelete(struct s_idsp *idsp, const int id) {
	int pos;
	int swp_id;
	int swp_pos;
	pos = idspGetPos(idsp, id);
	if(!(pos < 0)) {
		idsp->idfwd[id] = -1;
		swp_pos = --idsp->used;
		if(swp_pos != pos) {
			swp_id = idsp->idlist[swp_pos];
			idsp->idlist[swp_pos] = id;
			idsp->idlist[pos] = swp_id;
			idsp->idfwd[swp_id] = pos;
		}
	}
}


static int idspIsValid(struct s_idsp *idsp, const int id) {
	return (!(idspGetPos(idsp, id) < 0));
}


static int idspUsedCount(struct s_idsp *idsp) {
	return idsp->used;
}


static int idspSize(struct s_idsp *idsp) {
	return idsp->count;
}


static void idspDestroy(struct s_idsp *idsp) {
	idsp->used = 0;
	idsp->count = 0;
	free(idsp->idlist);
	free(idsp->idfwd);
}


#endif // F_IDSP_C
