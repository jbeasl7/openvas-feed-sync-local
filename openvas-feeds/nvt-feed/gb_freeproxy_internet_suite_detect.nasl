# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806894");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-17 11:03:06 +0530 (Tue, 17 May 2016)");
  script_name("Freeproxy Internet Suite Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Freeproxy Internet Suit.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

freePort = http_get_port(default:8080);
if(!rcvRes = http_get_cache( item:'/', port:freePort )){
  exit(0);
}

if('Server: FreeProxy' >< rcvRes)
{
   freeVer = eregmatch(pattern:"Server: FreeProxy/([0-9.]+)", string:rcvRes);

   if(freeVer[1]){
     version = freeVer[1];
   } else {
     version = "Unknown";
   }

   set_kb_item(name:"Freeproxy/installed", value:TRUE);
   set_kb_item(name:"Freeproxy/Ver", value:version);

   cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:freeproxy_internet_suite:freeproxy:");
   if(!cpe)
      cpe= "cpe:/a:freeproxy_internet_suite:freeproxy";

   register_product(cpe:cpe, location:"/", port:freePort, service:"www");

   log_message(data: build_detection_report(app: "Freeproxy internet suite",
                                            version: version,
                                            install: "/",
                                            cpe: cpe,
                                            concluded: version),
                                            port: freePort);
}

exit(0);
