# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107004");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"creation_date", value:"2016-05-20 10:42:39 +0100 (Fri, 20 May 2016)");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Meteocontrol WEB'log Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Meteocontrol WEB'log.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/html/en/index.html";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "WEB'log" >< buf && "System Survey of the Plant" >< buf
    && '<div class="cProductname">&nbsp;WEB&#180;log</div>' >< buf ) {

  set_kb_item( name:"meteocontrol/weblog/installed", value:TRUE );

  install = "/";
  # no version info available right now
  version = "unknown";

  cpe = "cpe:/a:meteocontrol:weblog";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Meteocontrol WEB'log",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:http_report_vuln_url( port:port, url:url, url_only:TRUE ) ),
               port:port );

}

exit( 0 );
