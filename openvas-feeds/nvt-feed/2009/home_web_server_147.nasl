# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100163");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Home Web Server Graphical User Interface Remote Denial Of Service Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HWS/banner");

  script_tag(name:"summary", value:"According to its version number, the remote version of the Home Web Server is
  prone to a denial-of-service vulnerability because it fails to adequately
  handle malformed HTTP requests.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the graphical interface of
  the server to stop responding, denying service to the administrator.");

  script_tag(name:"affected", value:"Home Web Server 1.7.1.147 is vulnerable. Other versions may also be
  affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34698");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || !egrep(pattern:"Server: .*\(HWS[0-9]+\)", string:banner) ) exit(0);

version = eregmatch(pattern: "HWS([0-9]+)", string: banner);
if(version[1] == "147") {
  security_message(port:port);
  exit(0);
}

exit(99);
