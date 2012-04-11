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


#ifndef F_NODEDB_C
#define F_NODEDB_C


#include "map.c"
#include "peeraddr.c"
#include "nodeid.c"
#include "util.c"


// The NodeDB data structure.
struct s_nodedb_data {
	struct s_peeraddr lastaddr;
	int lastseen;
	int lastconnect;
	int lastconntry;
};


// The NodeDB structure.
struct s_nodedb {
	struct s_map map;
	int max_age;
};


// Initialize NodeDB.
static void nodedbInit(struct s_nodedb *db) {
	mapInit(&db->map);
	mapEnableReplaceOld(&db->map);
}


// Update NodeDB entry.
static void nodedbUpdate(struct s_nodedb *db, struct s_nodeid *nodeid, struct s_peeraddr *addr, const int update_lastseen, const int update_lastconnect, const int update_lastconntry) {
	int tnow = utilGetTime();
	int id;
	struct s_nodedb_data *dbdata;
	struct s_nodedb_data newdata;
	if(nodeid != NULL) {
		memset(&newdata, 0, sizeof(struct s_nodedb_data));
		newdata.lastseen = 0;
		newdata.lastconnect = 0;
		newdata.lastconntry = 0;
		id = mapGetKeyID(&db->map, nodeid->id);
		if(!(id < 0)) {
			dbdata = mapGetValueByID(&db->map, id);
			newdata = *dbdata;
		}
		if(addr != NULL) {
			newdata.lastaddr = *addr;
		}
		if(update_lastseen > 0) {
			newdata.lastseen = tnow;
		}
		if(update_lastconnect > 0) {
			newdata.lastconnect = tnow;
		}
		if(update_lastconntry > 0) {
			newdata.lastconntry = tnow;
		}
		mapSet(&db->map, nodeid->id, &newdata);
	}
}


// Returns a node ID that matches the specified criteria.
static int nodedbNextID(struct s_nodedb *db, const int max_age, const int require_connect, const int require_waitretry) {
	int i, id, i_max, tnow;
	struct s_nodedb_data *dbdata;
	tnow = utilGetTime();
	i_max = mapGetKeyCount(&db->map);
	for(i=0; i<i_max; i++) {
		id = mapGetNextKeyID(&db->map);
		dbdata = mapGetValueByID(&db->map, id);
		if((db->max_age < 0) || ((tnow - dbdata->lastseen) < db->max_age)) {
			if(((max_age < 0) || ((tnow - dbdata->lastseen) < max_age)) && ((!(require_waitretry > 0)) || ((tnow - dbdata->lastconntry) >= ((tnow - dbdata->lastseen) / 2))) && ((!(require_connect > 0)) || ((tnow - dbdata->lastconnect) < max_age))) {
				return id;
			}
		}
		else {
			mapRemove(&db->map, mapGetKeyByID(&db->map, id));
		}
	}
	return -1;
}


// Returns node ID of specified NodeDB ID.
static struct s_nodeid *nodedbGetNodeID(struct s_nodedb *db, const int db_id) {
	return mapGetKeyByID(&db->map, db_id);
}


// Returns node address of specified NodeDB ID.
static struct s_peeraddr *nodedbGetNodeAddress(struct s_nodedb *db, const int db_id) {
	struct s_nodedb_data *dbdata = mapGetValueByID(&db->map, db_id);
	return &dbdata->lastaddr;
}


// Set maximum age of NodeDB entries in seconds (-1 = no limit).
static void nodedbSetMaxAge(struct s_nodedb *db, const int max_age) {
	if(max_age < 0) {
		db->max_age = -1;
	}
	else {
		db->max_age = max_age;
	}
}


// Create NodeDB.
static int nodedbCreate(struct s_nodedb *db, const int size) {
	if(mapCreate(&db->map, size, nodeid_SIZE, sizeof(struct s_nodedb_data))) {
		nodedbInit(db);
		nodedbSetMaxAge(db, -1);
		return 1;
	}
	return 0;
}


// Destroy NodeDB.
static void nodedbDestroy(struct s_nodedb *db) {
	mapDestroy(&db->map);
}


#endif // F_NODEDB_C
