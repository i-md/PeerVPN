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


#include <signal.h>
#include <stdio.h>
#include <openssl/engine.h>


#include "libp2psec/p2psec.c"
#include "platform/io.c"
#include "platform/ifconfig.c"
#include "globals.ic"
#include "helpers.ic"
#include "console.ic"
#include "ethernet.ic"
#include "mainloop.ic"
#include "config.ic"
#include "pwd.ic"
#include "init.ic"


// commandline parser
int main(int argc, char **argv) {
	int conffd;
	struct s_initconfig config;

	// default configuration
	strcpy(config.tapname,"");
	strcpy(config.ifconfig4,"");
	strcpy(config.ifconfig6,"");
	strcpy(config.upcmd,"");
	strcpy(config.sourceip,"");
	strcpy(config.sourceport,"");
	strcpy(config.userstr,"");
	strcpy(config.groupstr,"");
	strcpy(config.chrootstr,"");
	strcpy(config.networkname,"PEERVPN");
	strcpy(config.initpeers,"");
	strcpy(config.engines,"");
	config.password_len = 0;
	config.enableeth = 0;
	config.enablerelay = 0;
	config.enableindirect = 0;
	config.enableconsole = 0;
	config.enableprivdrop = 1;
	config.enableipv4 = 1;
	config.enableipv6 = 1;

	printf("PeerVPN v%d.%03d\n", PEERVPN_VERSION_MAJOR, PEERVPN_VERSION_MINOR);
	printf("(c)2012 Tobias Volk <mail@tobiasvolk.de>\n");
	printf("\n");

	switch(argc) {
	case 2:
		if(strncmp(argv[1],"-",1) == 0) {
			conffd = STDIN_FILENO;
			parseConfigFile(conffd,&config);
		}
		else {
			if((conffd = (open(argv[1],O_RDONLY))) < 0) throwError("could not open config file!");
			parseConfigFile(conffd,&config);
			close(conffd);
		}

		// start vpn node
		init(&config);
		break;		
	default:
		printf("usage: %s <path_to_config_file>\n", argv[0]);
		exit(0);
	}

	return 0;
}
