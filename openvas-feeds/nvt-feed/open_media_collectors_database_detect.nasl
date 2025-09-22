# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100468");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Open Media Collectors Database Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Open Media Collectors Database, a PHP and MySQL
  based inventory application.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/opendb/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

SCRIPT_DESC = "Open Media Collectors Database Detection";

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/opendb", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/login.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: "<title>Open Media Collectors Database - Login</title>", string: buf, icase: TRUE) &&
    "Powered by OpenDb" >< buf)
 {
    vers = "unknown";
    version = eregmatch(string: buf, pattern: "Powered by OpenDb ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) )
       vers = version[1];

    set_kb_item(name: "opendb/detected", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:opendb:opendb:");
    if (!cpe)
      cpe = 'cpe:/a:opendb:opendb';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Open Media Collectors Database", version: vers,
                                             install: install, cpe: cpe, concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
