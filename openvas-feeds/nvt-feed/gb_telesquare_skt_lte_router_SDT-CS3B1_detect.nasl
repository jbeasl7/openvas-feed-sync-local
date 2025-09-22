# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812366");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-28 10:46:29 +0530 (Thu, 28 Dec 2017)");
  script_name("Telesquare SKT LTE Router SDT-CS3B1 Detection");

  script_tag(name:"summary", value:"Detection of Telesquare SKT LTE Router SDT-CS3B1.

  The script sends a connection request to the server and attempts to detect the
  presence of the router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

ltePort = http_get_port(default:80);
res = http_get_cache( port:ltePort, item: "/" );

if("value='login'" >< res && "<title>Login to SDT-CS3B1<" >< res)
{
  version = "unknown";
  install = ltePort + "/tcp";

  set_kb_item( name:"telesquare/SDT-CS3B1/detected", value:TRUE );

  ##CPE not found, Creating new cpe
  cpe = "cpe:/h:telesquare:sdt-cs3b1";

  register_product(cpe:cpe, location:install, port:ltePort, service:"www");

  log_message(data: build_detection_report(app: "Telesquare SKT LTE Router SDT-CS3B1",
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: version),
                                           port: ltePort);
  exit(0);
}
exit(0);
