# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805740");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-23 12:30:00 +0530 (Wed, 23 Sep 2015)");
  script_name("Cisco Router SYNful Knock Implant");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://www2.fireeye.com/rs/848-DID-242/images/rpt-synful-knock.pdf");
  script_xref(name:"URL", value:"http://www.zdnet.com/article/synful-knock-cisco-router-malware-in-the-wild");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html");

  script_tag(name:"summary", value:"This host is a Cisco router which is compromised
  with the SYNful Knock implant.");

  script_tag(name:"vuldetect", value:"Send a crafted TCP packet request and
  check whether it is able to obtain valuable information or not");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain control of an affected device and compromise its integrity
  with a modified Cisco IOS software image.");

  script_tag(name:"affected", value:"Cisco 1841, Cisco 2811 and Cisco 3825 routers.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("http_func.inc");
include("port_service_func.inc");

dport = http_get_port(default:80);

ttl = 64;
saddr = this_host();
daddr = get_host_ip();
sport = rand() % (65536 - 1024) + 1024;

ip = forge_ip_packet(
     ip_hl    : 5,
     ip_v     : 4,
     ip_tos   : 0,
     ip_len   : 65535,
     ip_id    : 0x7f35,
     ip_off   : 0,
     ip_ttl   : 64,
     ip_p     : 6,
     ip_src   : saddr,
     ip_dst   : daddr);

tcppacket = forge_tcp_packet(
            ip : ip,
            th_sport : sport,
            th_dport : dport,
            th_flags : 0x02,
            th_seq   : 0,
            th_ack   : 0,
            th_off   : 5,
            th_win   : 1480,
            th_urp   : 0);

if(tcppacket && hexstr(tcppacket) =~ "020405b40101040201030305") {
  security_message(port:dport);
  exit(0);
}

exit(99);
