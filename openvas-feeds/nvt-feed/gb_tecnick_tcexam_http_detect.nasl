# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800792");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tecnick TCExam Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl",
                      "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Tecnick TCExam.");

  script_xref(name:"URL", value:"https://tcexam.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/tcexam", "/TCExam", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/public/code/index.php";

  res = http_get_cache( port:port, item:url );

  if( ( "TCExam" >< res || 'name="tcexam_level"' >< res ) && res =~ 'content=".?TCExam' ) {
    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # >TCExam</a> ver. 14.4.1
    vers = eregmatch( pattern:">\s+ver\.\s+([0-9.]+)", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
    } else {
      url = dir + "/VERSION";

      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # 15.0.1
      vers = eregmatch( pattern:"^([0-9.]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"tecnick/tcexam/detected", value:TRUE );
    set_kb_item( name:"tecnick/tcexam/http/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:tecnick:tcexam:" );
    if( ! cpe )
      cpe = "cpe:/a:tecnick:tcexam";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Tecnick TCExam", version:version, install:install,
                                               cpe:cpe, concluded:vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
