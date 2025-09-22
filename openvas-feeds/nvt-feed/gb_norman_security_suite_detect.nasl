# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_oid("1.3.6.1.4.1.25623.1.0.103693");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-10 13:55:18 +0200 (Wed, 10 Apr 2013)");
  script_name("Norman Security Suite Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2868);
  script_mandatory_keys("Norman_Security/banner");

  script_tag(name:"summary", value:"Detection of Norman Security Suite.

  The script sends a connection request to the server and attempts to
  detect Norman Security Suite from the reply.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:2868);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(!concl = egrep(string:banner, pattern:"Server: Norman Security", icase:TRUE))
  exit(0);

concl = chomp(concl);
vers = "unknown";
install = port + "/tcp";

set_kb_item(name:"norman_security_suite/installed", value:TRUE);

cpe = "cpe:/a:norman:security_suite";

register_product(cpe:cpe, location:install, port:port, service:"www");

log_message(data:build_detection_report(app:"Norman Security Suite (Njeeves.exe)", version:vers, install:install, cpe:cpe, concluded:concl, extra:"Njeeves.exe, part of Norman Security Suite is running at this port."),
            port:port);

exit(0);
