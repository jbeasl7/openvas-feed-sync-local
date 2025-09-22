# SPDX-FileCopyrightText: 2001 Noam Rathaus
# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10737");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle Applications One-Hour Install Detect");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam & Copyright (C) 2001 Noam Rathaus");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("oaohi/banner");
  script_require_ports("Services/www", 8002);

  script_tag(name:"solution", value:"Disable the Oracle Applications' One-Hour Install web server
  after you have completed the configuration, or block the web server's port on your Firewall.");

  script_tag(name:"summary", value:"We detected the remote web server as an Oracle
  Applications' One-Hour Install web server. This web server enables
  attackers to configure your Oracle Application server and Oracle Database
  server without any need for authentication.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8002);
banner = http_get_remote_headers(port:port);
if(! banner)
  exit(0);

if("Oracle Applications One-Hour Install" >< banner) {
  security_message(port:port);
  exit(0);
}

exit(99);
