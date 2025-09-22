# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800941");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SineCMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of SineCMS.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

sinePort = http_get_port(default:80);

if( !http_can_host_php( port:sinePort ) ) exit( 0 );

foreach dir (make_list_unique("/", "/sinecms", "/sine", http_cgi_dirs(port:sinePort)))
{

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:sinePort);

  if("SineCMS" >< rcvRes) {

    version = "unknown";

    sineVer = eregmatch(pattern:"SineCms Version: ([0-9.]+)", string:rcvRes);
    if(sineVer[1]!= NULL) version = sineVer[1];

    tmp_version = version + " under " + dir;
    set_kb_item(name:"www/" + sinePort + "/SineCMS", value:tmp_version);
    set_kb_item(name:"sinecms/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:sinecms:sinecms:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sinecms:sinecms';

    register_product( cpe:cpe, location:install, port:sinePort, service:"www" );

    log_message( data: build_detection_report( app:"SineCMS",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: sineVer[0]),
                                               port:sinePort);

  }
}
