# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900884");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenDocMan Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed OpenDocMan version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

docmanPort = http_get_port(default:80);

if(!http_can_host_php(port:docmanPort)) exit(0);

foreach dir (make_list_unique("/", "/docman", "/opendocman", http_cgi_dirs(port:docmanPort))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:docmanPort);

  if("Welcome to OpenDocMan" >!< rcvRes) {
    rcvRes = http_get_cache(item: dir + "/admin.php", port:docmanPort);
  }

  if("Welcome to OpenDocMan" >< rcvRes &&
     egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes)) {

    version = "unknown";

    docmanVer = eregmatch(pattern:"OpenDocMan v([0-9.]+)([a-z]+[0-9])?",
                          string:rcvRes);
    if(docmanVer[1]) {
      if(docmanVer[2]) {
        version = docmanVer[1] + "." + docmanVer[2];
      } else {
        version = docmanVer[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/"+ docmanPort + "/OpenDocMan",
                value:tmp_version);
    set_kb_item( name:"OpenDocMan/installed", value:TRUE );

    cpe = build_cpe(value:docmanVer, exp:"^([0-9.]+)", base:"cpe:/a:opendocman:opendocman:");
    if(isnull(cpe))
        cpe = 'cpe:/a:opendocman:opendocman';

    register_product( cpe:cpe, location:install, port:docmanPort, service:"www" );
    log_message( data:build_detection_report( app:"OpenDocMan",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded: docmanVer[0] ),
                 port: docmanPort);

  }
}
