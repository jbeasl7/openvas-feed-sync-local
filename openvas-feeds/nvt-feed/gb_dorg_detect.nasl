# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806696");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:58 +0530 (Wed, 06 Apr 2016)");
  script_name("Disc Organization System (DORG) Remote Version Detection");

  script_tag(name:"summary", value:"Detection of Disc Organization System (DORG).

  This script sends an HTTP GET request and checks for the presence of
  the application.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

dorgPort = http_get_port( default:80);

foreach dir(make_list_unique( "/", "/dorg", http_cgi_dirs(port:dorgPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  url = dir + "/admin_panel/index.php";

  dorgRes = http_get_cache(port:dorgPort, item: url);

  if(dorgRes =~ '<title>DORG.*admin panel<' && '>Disc Organization System<' >< dorgRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + dorgPort + "/dorg", value:version);
    set_kb_item( name:"DORG/Installed", value:TRUE);

    ##NO CPE NAME, taking CPE name as cpe:/a:dorg:dorg
    ##Need to update once CPE name is assigned
    cpe = "cpe:/a:dorg:dorg";

    register_product(cpe:cpe, location:install, port:dorgPort, service:"www");

    log_message( data:build_detection_report( app:"Disc Organization System - DORG",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:dorgPort);
  }
}
exit( 0 );
