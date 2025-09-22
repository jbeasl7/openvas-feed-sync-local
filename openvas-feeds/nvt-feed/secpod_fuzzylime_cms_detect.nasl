# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900583");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Fuzzylime(cms) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Fuzzylime(cms).");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

cmsPort = http_get_port(default:80);

if( !http_can_host_php( port:cmsPort ) ) exit( 0 );

foreach dir (make_list_unique("/cms", "/", "/docs", "/fuzzylime", http_cgi_dirs(port:cmsPort)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:cmsPort);

  if("fuzzylime (cms)" ><rcvRes)
  {

    version = "unknown";

    sndReq = http_get(item: dir + "/admin/includes/ver.inc.php", port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);
    if(egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes))
    {
      cmsVer = egrep(pattern:"^([0-9]\.[0-9]+)", string:rcvRes);
      cmsVer = eregmatch(pattern:"([0-9.]+[a-z]?)", string:cmsVer);
    }
    else
    {
      sndReq = http_get(item: dir + "/docs/readme.txt", port:cmsPort);
      rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);
      if("fuzzylime (cms)" >< rcvRes){
        cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
      }
    }
    if(cmsVer[1] != NULL) version = cmsVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/"+ cmsPort + "/Fuzzylime(cms)", value:tmp_version);
    set_kb_item(name:"fuzzylimecms/installed", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:fuzzylime:fuzzylime_cms:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:fuzzylime:fuzzylime_cms';

    register_product( cpe:cpe, location:install, port:cmsPort, service:"www" );

    log_message( data: build_detection_report( app:"Fuzzylime(cms)",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:cmsVer[0]),
                                               port:cmsPort);

  }
}
