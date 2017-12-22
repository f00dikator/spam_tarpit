#include "./spam.h"
/*
 * * This software was written by John Lampe (jwlampe@nessus.org)
 * * I don't care if you use it...
 * * Compile with 
 * * gcc spam_tarpit.c -o tarpit -lnet -lpcap
 * * or just run ./build from this directory
*/



int do_somethin(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	unsigned long l_src_ip, l_dst_ip;
	libnet_t *l;
	int len, ip_hl, srcport, SYN, ACK, myflags, ret, tcp_hl, data = 0, ehlo = 0, starttls = 0, expn = 0, vrfy = 0, mailfrom = 0, rcpt = 0, winsize = 0, arbitrary = 0;
	int undata = 1;
	int rset = 0, scounter, quit = 0, xflags = 0, data_length = 0, help = 0;
	int myrand, mywin;
	libnet_ptag_t tcpp, ipp;
	u_long seq_num, ack_num;
	char *srchost;
	const struct my_ip *mip;
    	u_int length = pkthdr->len;
        u_int hlen,version;
	//char *mydata = NULL, *req = NULL;
	char *mydata = NULL;
	u_char *req = NULL;
        /*char all[] = "250 Yo there mein compadre, sit a spell ;-)\r\n250 2.1.0 ... Sender OK\r\n250 2.1.5 Recipient ok\r\n";
        char init[] = "220 relay.netsecuregroup.com ESMTP Sendmail Enterprise/9.500.300;\r\n";
        char rsetok[] = "250 Reset state.  Southern hospitality dictates that you sit for a spell\r\n";
        char one[] = "250 Yo there mein compadre, sit a spell.  Southern hospitality dictates that you sit for a spell\r\n";
        char senderok[] = "250 2.1.0 <.@.>... Sender ok\r\n";
        char recipok[] = "250 2.1.5 Recipient ok\r\n";
        char two[] = "250 Yo there mein compadre, sit a spell ;-)\r\n250 2.1.0 ... Sender OK\r\n";
        char middle[] = "250 2.1.0 <.@.>... Sender ok\r\n250 2.1.5 Recipient ok\r\n";
	char helpsucks[] = "214-2.0.0 This is sendmail version DaShiznet\r\n";
	char feedmecmore[] = "354 Ok Send data ending with <CRLF>.<CRLF>\r\n";
	*/

	// PCRE Variables
        pcre *re;
        const char *error;
        int erroffset, rc;
        int ovector[30];
	

	if (MDEBUG)
		printf("\n\n\n\n***** PACKET DEBUG ********");

	SYN = ACK = myflags = 0;
	req = mydata = NULL;

        /* initialize the libnet */
	l = libnet_init(
	                LIBNET_RAW4,
	                NULL,
	                errbuf);
        if (l == NULL)
        {
        	fprintf(stderr, "libnet_init() failed %s\n", errbuf);
	        libnet_destroy(l);
	        return(0);
	}


    	mip = (struct my_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header); 

    	if (length < sizeof(struct my_ip))
       	{
		if (MDEBUG)	
	    		printf("truncated IP %d",length);
		libnet_destroy(l);
		return (0);
	}

        len     = ntohs(mip->ip_len);
    	hlen    = IP_HL(mip); 
	version = IP_V(mip);

	if (hlen < 5)
	{
		if (MDEBUG)
			fprintf(stdout,"bad-hlen %d \n",hlen);
		libnet_destroy(l);
		return (0);
	}

	if (length < len)
	{
		if (MDEBUG)
			printf("\ntruncated IP - %d bytes missing\n",len - length);
		libnet_destroy(l);
		return (0);
	}

	srchost = inet_ntoa(mip->ip_src);

	l_src_ip = libnet_name2addr4(l,mysrcip,LIBNET_DONT_RESOLVE);
	if (l_src_ip == -1)
	{
		fprintf (stderr,"Error with l_src_ip\n");
		libnet_destroy(l);
		return(0);
	}

	if (MDEBUG)
		printf("ip_src is %s\n", inet_ntoa(mip->ip_src));

	l_dst_ip = libnet_name2addr4(l,inet_ntoa(mip->ip_src),LIBNET_DONT_RESOLVE);

	if (l_dst_ip == -1)
	{
		fprintf(stderr,"Error with l_dst_ip\n");
		libnet_destroy(l);
		return(0);
	}



	if (packet[23] == 0x06) 
	{
		length = (packet[16] << 8) + packet[17];
		ip_hl = (packet[14] & 0x0f) << 0x02;
		srcport = (packet[14 + ip_hl] << 8)  + packet[15 + ip_hl];

		/* wrt ack and seq nums on non-data packets
		 * when we spoof a packet:
		 * spoofed seq_num will be equal to last received ack_num
		 * spoofed ack_num will be last received seq_num + 1
		 */

		ack_num = (packet[18 + ip_hl] << 24) + (packet[19 + ip_hl] << 16) + 
			  (packet[20 + ip_hl] << 8) + packet[21 + ip_hl] + 1;

		seq_num = (packet[22 + ip_hl] << 24) + (packet[23 + ip_hl] << 16) +
			  (packet[24 + ip_hl] << 8) + packet[25 + ip_hl];

		tcp_hl = ((packet[26 + ip_hl] & 0xf0) >> 2);
	
		data_length = length - ip_hl - tcp_hl;

		myflags = packet[27 + ip_hl] & 0x3f;
		


		if (0x10 & myflags)
			ACK = 1;

		if (0x02 & myflags)
			SYN = 1;

		if (SYN && ACK)
		{
			if (MDEBUG)
				printf("HAHA.  The SMTP client just sent a SYN-ACK packet.  stupid rabbit!\n");
			libnet_destroy(l);
			return (0);	
		}


		
		if (ACK)
		{
			/* if we have a string starting with EHLO/HELO/MAIL/RCPT then send back a banner
			 * else, send back an ACK with win_size = 0
			 * char *strstr(const char *haystack, const char *needle);
			 */

			mydata = &packet[14 + ip_hl + tcp_hl];
			if (MDEBUG)
				printf ("Caught an ACK packet.  data size is %d bytes\n", data_length);


			/* 0-data is an ACK packet...which we won't ACK.  A 1-byte packet is probably a TCP window-probe
			 * so we'll keep req == NULL and winsize == 0 */
			if ( ( data_length <= 1) || (! isprint(packet[14 + ip_hl + tcp_hl])) )
			{
				if ( (data_length == 1) && (isprint(packet[14 + ip_hl + tcp_hl])) )
				{
					// this is prolly a window probe
					if (MDEBUG)
						printf("caught a 1-byte window probe.  Windows goes to 0x0\n");
					req = NULL;
					winsize = 0x00;	
					ack_num--;
                                        sprintf(mylog, "%s is still STUCK in tarpit", inet_ntoa(mip->ip_src));
				        syslog(LOGTYPE, mylog);

				}
				else if ( (data_length == 1) && (! isprint(packet[14 + ip_hl + tcp_hl])) )
				{
					if (MDEBUG)
						printf("received a 1-byte data packet which was unprintable. \n");
					req = NULL;
					winsize = 0x00;
					ack_num--;
					sprintf(mylog, "%s is still STUCK in tarpit", inet_ntoa(mip->ip_src));
					syslog(LOGTYPE, mylog);
				}
				else
				{
					// if first ACK after our SYN|ACK, we need to send a 220
					// below is kludge to be fixed later
					if ( (current == srchost) && (data_length == 0) )
					{
						if (MDEBUG)
							printf("Sending the first 220 off.  Setting current to \"d\"\n");
						current = "d";
						req = init;
						winsize = strlen(req);
						ack_num--;
					}
					else if ( (current == srchost) && (data_length > 0) )
					{
						if (MDEBUG)
						{
							printf("Odd...a data packet during the TCP setup phase\n");
							printf ("Packet Size: %d\n", strlen(mydata));
							printf ("Data: %s\n", mydata);
							printf("Sending the first 220 off.  Setting current to \"d\"\n");
						}
						current = "d";
						req = init;
						winsize = strlen(req);
						ack_num--;
					}
					else
					{
						if (MDEBUG)
							printf("A packet fell through the if/else.  destroyed\n");
						libnet_destroy(l);
						return(0);
					}
				}
			}
			else
			{
				/* if we get to here, then we know we have a data packet which is greater than 1 byte 
				 * or we have an unprintable data char  */
				if (MDEBUG)
					printf("Incoming data packet: %s\n", mydata);

				re = pcre_compile("^[eE][xX][pP][nN].*",0,&error,&erroffset,NULL);
			
				if (error)
                                {
                                        if (MDEBUG)
                                                printf("PCRE ERROR %s\t%d\n", error, erroffset);
                                }

                                rc = pcre_exec(re,NULL,mydata,strlen(mydata), 0,0,ovector,30);

                                if (rc>=1)
                                {
                                        if (MDEBUG)
                                                printf("STATE EXPN\n");
                                        expn = 1;
                                        ack_num = ack_num + strlen(mydata) - 1;
                                }

				re = pcre_compile("^[vV][rR][fF][yY].*",0,&error,&erroffset,NULL);

                                if (error)
                                {
                                        if (MDEBUG)
                                                printf("PCRE ERROR %s\t%d\n", error, erroffset);
                                }

                                rc = pcre_exec(re,NULL,mydata,strlen(mydata), 0,0,ovector,30);

                                if (rc>=1)
                                {
                                        if (MDEBUG)
                                                printf("STATE VRFY\n");
                                        vrfy = 1;
                                        ack_num = ack_num + strlen(mydata) - 1;
                                }



				re = pcre_compile("^[sS][tT][aA][rR][tT][tT][lL][sS].*",0,&error,&erroffset,NULL);
			
				if (error)
                                {
                                        if (MDEBUG)
                                                printf("PCRE ERROR %s\t%d\n", error, erroffset);
                                }

				rc = pcre_exec(re,NULL,mydata,strlen(mydata), 0,0,ovector,30);

                                if (rc>=1)
                                {
                                        if (MDEBUG)
                                                printf("STATE STARTTLS\n");
                                        starttls = 1;
                                        ack_num = ack_num + strlen(mydata) - 1;
                                }


                 		re = pcre_compile("^([eEhH][hHeE][lL][oO]) .*",0,&error,&erroffset,NULL);

				/* pcre_extra *hints;
				 * hint = pcre_study(re, 0, &error);
				 * if (error != NULL)
				 * {
				 *   fprintf(stderr, "pgrep: error while studing regex: %s\n", error);
				 *   return 2;
				 * } 
				 * rc = pcre_exec(re,hints,mydata,strlen(mydata), 0,0,ovector,30); */

		                if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata), 0,0,ovector,30);
				
				if (rc>=1)
				{
					if (MDEBUG)
						printf("STATE EHLO\n");
					ehlo = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}

				// f00dikator
				re = pcre_compile("^([mM][aA][iI][lL] [fF][rR][oO][mM]):.*",0,&error,&erroffset, NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);

				if (rc>=1)
				{
					if (MDEBUG)
						printf("STATE MAIL-FROM\n");
					mailfrom = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}
				
				re = pcre_compile("^([rR][cC][pP][tT] [tT][oO]):.*",0,&error,&erroffset,NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);

				if (rc>=1)
				{
					if (MDEBUG)
						printf("STATE RCPT TO\n");
					rcpt = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}
				

				re = pcre_compile("^([dD][aA][tT][aA])",0,&error,&erroffset,NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);

				if (rc>=1)
				{
					if (MDEBUG)
						printf("STATE DATA\n");
					data = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}
						

				re = pcre_compile("^([rR][sS][eE][tT])",0,&error,&erroffset,NULL);
				
				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);

				if (rc>=1)
				{
					if (MDEBUG)
						printf("STATE RSET\n");
					rset = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}

				re = pcre_compile("^([qQ][uU][iI][tT])",0,&error,&erroffset,NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);
			
				if (rc>=1)	
				{
					if (MDEBUG)
						printf("STATE QUIT\n");
					quit = 1;
					ack_num--;
					xflags = 1;
				}

				re = pcre_compile("^([hH][eE][lL][pP])",0,&error,&erroffset,NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);
				
				if (rc>=1)	
				{
					if (MDEBUG)
						printf("STATE HELP\n");
					help = 1;
					ack_num = ack_num + strlen(mydata) - 1;
				}

				re = pcre_compile("^([dD][aA][tT][eE]|[sS][uU][bB][jJ][eE][cC][tT]|[tT][oO]|X-[a-zA-Z-]+|Message-I[dD]|From|User-Agent|[mM][iI][mM][eE]-[a-zA-Z]+|Content-[tT]ype|Received|[a-zA-Z_]+):.*",0,&error,&erroffset,NULL);

				if (error)
				{
					if (MDEBUG)
						printf("PCRE ERROR %s\t%d\n", error, erroffset);
				}

				rc = pcre_exec(re,NULL,mydata,strlen(mydata),0,0,ovector,30);
			
				if (  (rc>=1) && (ehlo != 1) && (mailfrom != 1) && (rcpt != 1) &&	
						(data != 1) && (rset != 1) && (quit != 1) && (help != 1) )
				{
					if (MDEBUG)
						printf("STATE Arbitrary data\n");
					arbitrary = 1;
					ack_num--;
				}

				if (  (rc<1) && (strlen(mydata) > 15) && (ehlo != 1) && (mailfrom != 1) && (rcpt != 1) &&
						(data != 1) && (rset != 1) && (quit != 1) && (help != 1) )
				{
					if (MDEBUG)
						printf("Yo, this is just freaking wierd...somehow we are in the middle of the message\n");
					arbitrary = 1;
					ack_num--;
				}


				if ( (arbitrary != 1) && (ehlo != 1) && (mailfrom != 1) && (rcpt != 1) &&
						(data != 1) && (rset != 1) && (quit != 1) && (help != 1) && (data_length > 1) )
				{
					if (MDEBUG)
						printf("We have some wierd non-SMTP header data\n");
					ack_num = ack_num + strlen(mydata) - 1;
				}

				if (ehlo && mailfrom && rcpt)		// all the headers at once
				{
					req = all;
					winsize = strlen(req);
                                        if (MDEBUG)
                                        	printf("Setting req to %s\n", req);
				} 
				else if (ehlo && (! mailfrom) )		// just EHLO
				{
					req = one;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (starttls)
				{
					req = starttls_msg;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (expn)
				{
					req = expn_msg;
					winsize = strlen(req);
                                        if (MDEBUG)
                                                printf("Setting req to %s\n", req);

				}
				else if (vrfy)
				{
					req = vrfy_msg;
					winsize = strlen(req);
                                        if (MDEBUG)
                                                printf("Setting req to %s\n", req);

				}
				else if ((! ehlo) && mailfrom)		// just mailfrom
				{
					req = senderok;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if ((! ehlo) && (! mailfrom) && rcpt)	// just RCPT TO
				{
					req = recipok;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (ehlo && mailfrom && (! rcpt) )	// EHLO and mailfrom only
				{
					req = two;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if ( (! ehlo) && mailfrom && rcpt)
				{
					req = middle;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (data)				//DATA
				{
					req = feedmecmore;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (rset)				//RSET
				{
					req = rsetok;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (help)
				{
					req = helpsucks;
					winsize = strlen(req);
					if (MDEBUG)
						printf("Setting req to %s\n", req);
				}
				else if (arbitrary)
				{
					req = NULL;
					winsize = 0x00;
					if (MDEBUG)
						printf ("Tarpitting %s\n", inet_ntoa(mip->ip_src));
					sprintf(mylog, "SPAM-TARPIT: Tarpitting %s", inet_ntoa(mip->ip_src));
					syslog(LOGTYPE, mylog);
				}
				else
				{
					if (current != "d")
					{
						// well now, this is a pickle....we've not yet sent off the init
						// packet, yet here we are getting data from the client.  That's totally 
						// bogus.
						// let's clean up our data buffers and return to main()
						if (MDEBUG)
						{
							printf("BOGUS DATA PACKET!  data packet sent before our init\n");
							printf("Data sent was %s\n", mydata);
						}

						for (scounter = 1; scounter > 0; scounter++)
					        {
					        	if ( (mydata[scounter] == NULL) || (mydata[scounter] == 0x00) )
						        	scounter = -1;
						        else
						                mydata[scounter] = 0x00;
						        if (scounter > 1024)
						        	scounter = -1;
					         }
						 libnet_destroy(l);
						 return(0);
					}
					else
					{
						// we have a data packet.
						// The data packet doesn't match any of our pre-data headers
						// we've already sent off our INIT packet
						if (MDEBUG)
						{
							printf("We snagged a data packet which doesn't match\n");
							printf ("and we've already sent INIT!!!\n");
							printf ("data packet is %s\n", mydata);
							printf ("ACKING this unknown data packet with winsize = 1\n");
						}
						//libnet_destroy(l);
						//return(0);
						req = NULL;
						winsize = 0x01;	
						undata = 0x00;
					}
				}
			}
			if (MDEBUG)
			{
				if (req == NULL)	
					printf("req is NULL and winsize is %d\n", winsize);
			}

			//tcpp = LIBNET_PTAG_INITIALIZER;

			if (MDEBUG)
			{
				printf("\tCreating Packet:\n");
				printf("\tsrcport:%d dstport:%d sequence:%d\n", PORT, srcport, seq_num & 0xFFFFFFFF);
				printf("\tAck:%d flags:%d\n", ack_num & 0xFFFFFFFF, (xflags == 1) ? TH_RST : TH_ACK);
				printf("\twindow:%d\n", ((req == NULL) && (winsize == 0x00)) ? 0 : 1024);
				printf("\tTCP Packet size: %d\n", LIBNET_TCP_H + winsize);
				printf("\tPayload:%s\n", (req == NULL) ? NULL : req);
				printf("\tPayload size:%d\n",(req == NULL) ? 0 : winsize);
			}

			if ( (req == NULL) && (winsize == 0x00) )
			{
				// 33% of time we'll let the win recv be 1 byte
				myrand = rand() % 3;
				if ( (myrand % 2) == 0)
				{
					mywin = 0;
				}
				else
				{
					mywin = myrand;
				}
			}
			
			tcpp = libnet_build_tcp(
				PORT,								//src port
				srcport,							//dst port
				seq_num,							//sequence number
				ack_num,							// ack num
				(xflags == 1) ? TH_RST : TH_ACK,				// flags
				((req == NULL) && (winsize == 0x00)) ? mywin : 1024,		//window size
				0,								// checksum		
				0,								// urgent pointer
				(undata == 1) ? LIBNET_TCP_H + winsize : LIBNET_TCP_H ,		// tcp packet size
				(req == NULL) ? NULL : req,					//payload
				((req == NULL)&&(undata==0)) ? 0 : winsize,			// payload size
				l,								// fd
				0);								//libnet ID

			if (tcpp == -1)
			{
				printf ("libnet_build_tcp() error1 %s\n", libnet_geterror(l));
				libnet_destroy(l);
				return(0);
			}


			ipp = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + winsize,			// total LEN IP + TCP + data
				0,							// TOS
				rand() % 65536,						// ID
				0,							// FRAG
				128,							// TTL
				IPPROTO_TCP,						// PROTO
				0,							//checksum
				l_src_ip,						// src
				l_dst_ip,						// dst
				NULL,							// payload
				0,							// payload size
				l,							// descriptor
				0);							// ptag
			
			if (ipp == -1)
			{
				printf("Error with libnet_build_ipv4()\n");
			        libnet_destroy(l);
			        return(0);
			}	
			
			ret = libnet_write(l);
			if (ret == -1)
			{
				printf("Error with libnet_write()\n");
				libnet_destroy(l);
				return(0);
			}
			libnet_destroy(l);

			for (scounter = 1; scounter > 0; scounter++)
			{
				if ( (mydata[scounter] == NULL) || (mydata[scounter] == 0x00) )
					scounter = -1;
				else
					mydata[scounter] = 0x00;
				if (scounter > 1024)
					scounter = -1;
			}
			
			return(0);
		}
		else if (SYN)
		{
			sprintf(mylog, "SPAM-TARPIT: caught a nibble from %s", inet_ntoa(mip->ip_src)); 
			syslog(LOGTYPE, mylog);
			seq_num = (rand() % 31338) + 5;		
			tcpp = LIBNET_PTAG_INITIALIZER;
			tcpp = libnet_build_tcp(
				PORT,			
				srcport,
				seq_num,			// sequence number = to last ack num
				ack_num,			// Ack number = to last seq_num + 1
				TH_SYN|TH_ACK,			// FLAGS
				0xFFFF,				// windows size
				0,
				0,
				LIBNET_TCP_H,
				NULL,
				0,
				l,
				tcpp);

			
			if (tcpp == -1)
			{
				printf ("libnet_build_tcp() error2 %s\n", libnet_geterror(l));
				libnet_destroy(l);
				memset(&packet, 0, sizeof(packet));
				return(0);
			}

			ipp = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H,
				0,
				rand() % 65536,
				0,
				128,
				IPPROTO_TCP,
				0,
				l_src_ip,
				l_dst_ip,
				NULL,
				0,
				l,
				0);
			
			if (ipp == -1)
			{
				printf("Error with libnet_build_ipv4()\n");
				libnet_destroy(l);
				memset(&packet, 0, sizeof(packet));
				return(0);
			}

			ret = libnet_write(l);
			if (ret == -1)
			{
				printf("Yo, some whacky write() error. %s\n", libnet_geterror(l));	
				libnet_destroy(l);
				memset(&packet, 0, sizeof(packet));
				return(0);
			}
			else
			{
				current = srchost;
				if (MDEBUG)
				{
					printf("Initial SYN/ACK Packet sent\n");
					printf("setting current equal to %s\n", srchost);
				}
			}
		}
		else
		{
			libnet_destroy(l);
			memset(&packet, 0, sizeof(packet));
			return (0);
		}

	}
	else
	{
		fprintf(stderr, "Packet is not a TCP packet\n");
	}

	libnet_destroy(l);
	return (0);
}





int main(int argc, char **argv)
{
	pcap_t *ptr;
	struct bpf_program fp;
	bpf_u_int32 ip;

	
	/* initialize the pcap */
	ptr = pcap_open_live(device,MYMAX,1,-1,errbuf);
	if(ptr == NULL)
	{
		printf("Bad call to pcap_open_live(): %s\n", errbuf);
		exit(1);
	}

	if(pcap_compile(ptr,&fp, filter, 0, ip) == -1)
   	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1); 
	}

   	if(pcap_setfilter(ptr,&fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}

	if (pcap_datalink(ptr) != DLT_EN10MB)
	{
		fprintf(stderr,"Error: Only Ethernet interfaces supported\n");
		exit(1);
	}
	
	while (1)
		pcap_loop(ptr,500,do_somethin,NULL);	

	return (0);
}



