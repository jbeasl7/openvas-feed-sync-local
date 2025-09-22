# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808219");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)");
  script_name("Moxa EDR G903 Router Remote Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Moxa EDR G903 Router.

  This script sends an HTTP GET request and checks for the presence of Moxa EDR G903
  Router from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

edrPort = http_get_port( default:80 );
if( ! http_can_host_asp( port:edrPort ) )
  exit( 0 );

url = "/Login.asp";

res = http_get_cache(item:url, port:edrPort);

#Project model is different for different edr series
if("<TITLE>Moxa EDR</TITLE>" >< res && "Moxa EtherDevice Secure Router" >< res &&
   "Username :" >< res && "Password :" >< res &&
   ("ProjectModel = 1" >< res || ">EDR-G903<" >< res))
{
  edrVer = "Unknown";

  set_kb_item(name:"Moxa/EDR/G903/Installed", value:TRUE);

  cpe = "cpe:/h:moxa:edr-g903";

  register_product(cpe:cpe, location:"/", port:edrPort, service:"www");

  log_message(data: build_detection_report(app: "Moxa EDR G903 Router",
                                           version: edrVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: edrVer),
                                           port: edrPort);
}
