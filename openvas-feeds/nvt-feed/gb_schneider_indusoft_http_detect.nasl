# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141011");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-19 13:02:45 +0700 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric InduSoft Web Studio Detection");

  script_tag(name:"summary", value:"Detection of Schneider Electric InduSoft Web Studio.

  The script sends a connection request to the server and attempts to detect Schneider Electric InduSoft Web Studio
  and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 81, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.indusoft.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("ISSymbol1.ProductName" >< res && "InduSoft Web Studio" >< res) {
  set_kb_item(name: "schneider_indusoft/installed", value: TRUE);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/detected", value: TRUE);

  version = "unknown";
  concluded = "HTTP Request";

  vers = eregmatch(pattern: 'ProductVersion = "([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = vers[0];
  }

  set_kb_item(name: "schneider_indusoft/http/" + port + "/version", value: version);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/concluded", value: vers[0]);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/location", value: "/");
  set_kb_item(name: "schneider_indusoft/http/port", value: port);
}

exit(0);
