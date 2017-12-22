/*
 * ** This software was written by John Lampe (dmitry.chan@gmail.com)
 * ** I don't care if you use it...
 * ** Compile with
 * ** gcc spam_tarpit.c -o tarpit -lnet -lpcap
 * ** or just run ./build from this directory
 * **     */

#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <pcre.h>
#define MYMAX 1024
#define MDEBUG 0
#define LOGTYPE LOG_WARNING


// User-defined STUFF
char mysrcip[]   = "172.26.36.100";                                 		
char *device = "eth5";
char filter[] = "tcp and (dst port 25) and (dst 172.26.36.100)";
int PORT = 25;
char all[] = "250 Tenable open mail relay.  Pleased to meet you ;-)\r\n250 2.1.0 ... Sender OK\r\n250 2.1.5 Recipient ok\r\n";
char init[] = "220 ElDuderino.tenable.com ESMTP Sendmail Enterprise/1.0 at D4.5h.1z.net<script>alert('hi')</script>\r\n";
char rsetok[] = "250 Reset state.  Southern hospitality dictates that you sit for a spell\r\n";
char one[] = "250 Welcome to Tenable open mail relay.  Pleased to meet you ;-)\r\n";
char senderok[] = "250 2.1.0 <.@.>... Sender ok\r\n";
char recipok[] = "250 2.1.5 Recipient ok\r\n";
char two[] = "250 Welcome to Tenable open mail relay.  Pleased to meet you ;-)\r\n250 2.1.0 ... Sender OK\r\n";
char middle[] = "250 2.1.0 <.@.>... Sender ok\r\n250 2.1.5 Recipient ok\r\n";
char helpsucks[] = "214-2.0.0 This is sendmail version D4.5h.1z.net\r\n";
char feedmecmore[] = "354 Ok Send data ending with <CRLF>.<CRLF>\r\n";
char starttls_msg[] = "220 Go ahead with your bad self, but for the record TLS is for WUSSIES!\r\n";
char expn_msg[] = "250 Rest assured your best interest is of paramount importance sire\r\n";
char vrfy_msg[] = "252 I'm not in a position to really verify anything, but go ahead and send anyway\r\n";
// end User-defined

char *current;
char mylog[1024];
char errbuf[1024];

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};




