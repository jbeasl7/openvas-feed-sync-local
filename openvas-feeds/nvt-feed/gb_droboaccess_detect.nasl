# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142073");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-03-06 09:53:10 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo DroboAccess Detection");

  script_tag(name:"summary", value:"Detection of Drobo DroboAccess.

The script sends a connection request to the server and attempts to detect Drobo DroboAccess, a web interface
for Drobo NAS devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8060);

if (!http_can_host_php(port: port))
  exit(0);

# This seems to be the login page which differs from the admin page
res = http_get_cache(port: port, item: "/index.php/login");

if ("Drobo Access" >< res && 'class="infield">Password' >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/port", value: port);
}

# The "admin" page which is normally on another port (8080)
res = http_get_cache(port: port, item: "/DroboAccess/");

if ("title>DroboAccess DroboApp</title>" >< res && "Password strength" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/port", value: port);
}

exit(0);
