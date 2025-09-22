# SPDX-FileCopyrightText: 2009 Vlatko Kosturjak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80101");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-03-14 09:49:01 +0100 (Sat, 14 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_copyright("Copyright (C) 2009 Vlatko Kosturjak");
  script_name("SGI Objectserver vuln");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(5135);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"IRIX object server is installed on this host.

  There are various security bugs in the implementation of this service which can
  be used by an intruder to gain a root account rather easily.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if(TARGET_IS_IPV6())
  exit(0);

port = 5135;
if(!get_udp_port_state(port))
  exit(0);

numer_one = raw_string(0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00, 0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00);
numer_two = raw_string(0x21,0x03,0x00,0x43,0x00,0x0a,0x00,0x0a, 0x01,0x01,0x3b,0x01,0x6e,0x00,0x00,0x80, 0x43,0x01,0x01,0x18,0x0b,0x01,0x01,0x3b, 0x01,0x6e,0x01,0x02,0x01,0x03,0x00,0x01, 0x01,0x07,0x01,0x01);

targetip = get_host_ip();

ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_tos:0,
                     ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
                     ip_src:this_host());

sport = rand() % 64512 + 1024;
req = numer_one + numer_two;

u = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:port, uh_ulen:8 + strlen(req), data:req);
filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + '';

gotvuln = FALSE;
cmpdata = raw_string(0x0a,0x01,0x01,0x3b,0x01,0x78);

for(i = 0; i < 2; i++) { # Try twice
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
  if(rep) {
    data = get_udp_element(udp:rep, element:"data");
    if(cmpdata >< data) {
      gotvuln = TRUE;
    }
  }
}

if(gotvuln == TRUE) {
  security_message(port:port, proto: "udp");
  exit(0);
}

exit(99);
