# SPDX-FileCopyrightText: 2008 Tim Brown and Portcullis Computer Security Ltd
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80096");
  script_version("2024-06-07T05:05:42+0000");
  script_cve_id("CVE-2008-5849");
  script_tag(name:"last_modification", value:"2024-06-07 05:05:42 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2008-11-05 16:59:22 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Check Point VPN-1 PAT Information Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK); # nb: Could be already seen as an attack
  script_family("General");
  script_copyright("Copyright (C) 2008 Tim Brown and Portcullis Computer Security Ltd");
  script_dependencies("global_settings.nasl");
  script_require_ports(18264);
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://web.archive.org/web/20110810185306/http://www.portcullis-security.com/293.php");

  script_tag(name:"summary", value:"Check Point VPN-1 PAT is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks the response.");

  script_tag(name:"insight", value:"By sending crafted packets to ports on the firewall which are
  mapped by port address translation (PAT) to ports on internal devices, information about the
  internal network may be disclosed in the resulting ICMP error packets.

  Port 18264/tcp on the firewall is typically configured in such a manner, with packets to this port
  being rewritten to reach the firewall management server.

  For example, the firewall fails to correctly sanitise the encapsulated IP headers in ICMP
  time-to-live exceeded packets resulting in internal IP addresses being disclosed.

  False positive:

  This could be false positive alert. Try running same scan against single host where this
  vulnerability is reported.");

  script_tag(name:"solution", value:"We are not aware of a vendor approved solution at the current
  time.

  On the following platforms, we recommend you mitigate in the described manner:

  - Checkpoint VPN-1 R55

  - Checkpoint VPN-1 R65

  We recommend you mitigate in the following manner:

  Disable any implied rules and only open ports for required services Filter outbound ICMP
  time-to-live exceeded packets.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");

if(TARGET_IS_IPV6() || islocalhost())
  exit(0);

port = 18264;
if (!get_port_state(port))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

close(soc);

function packet_construct(_ip_src, _ip_ttl) {
  _ip_id = rand() % 65535;
  _th_sport = (rand() % 64000) + 1024;
  _ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:_ip_id, ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, ip_src:_ip_src, ip_ttl:_ip_ttl);
  _tcp = forge_tcp_packet(ip:_ip, th_sport:_th_sport, th_dport:18264, th_flags:TH_SYN, th_seq:_ip_ttl, th_ack:0, th_x2:0, th_off:5, th_win:2048, th_urp:0);
  return _tcp;
}

function packet_parse(_icmp, _ip_dst, _ttl) {

  _ip = get_icmp_element(icmp:_icmp, element:"data");
  _ip_p = get_ip_element(ip:_ip, element:"ip_p");
  _ip_dst2 = get_ip_element(ip:_ip, element:"ip_dst");
  _ip_hl = get_ip_element(ip:_ip, element:"ip_hl");
  _tcp = substr(_ip, (_ip_hl * 4), strlen(_ip));
  _ih_dport = (ord(_tcp[2]) * 256) + ord(_tcp[3]);
  _data = "";
  if ((_ip_p == IPPROTO_TCP) && (_ip_dst2 != _ip_dst) && (_ih_dport == 18264)) {
    _data = "Internal IP disclosed: " + _ip_dst2 + " (ttl: " +_ttl + ')\n';
    set_kb_item(name:"Checkpoint/Manager/ipaddress", value:_ip_dst2);
  }
  return _data;
}

sourceipaddress = this_host();
destinationipaddress = get_host_ip();
packetfilter = "dst host " + sourceipaddress + " and icmp and (icmp[0]=11)";
reportout = "";
for (ttl = 1; ttl <= 50; ttl++) {
  requestpacket = packet_construct(_ip_src:sourceipaddress, _ip_ttl:ttl);
  responsepacket = send_packet(requestpacket, pcap_active:TRUE, pcap_filter:packetfilter, pcap_timeout:1);
  if (responsepacket) {
    reportdata = packet_parse(_icmp:responsepacket, _ip_dst:destinationipaddress, _ttl:ttl);
    reportout = reportout + reportdata;
  }
}

if (reportout != "") {
  reportheading = "Disclosures:";
  wholereport = reportheading + reportout;
  security_message(port:port, data:wholereport);
  exit(0);
}

exit(99);
