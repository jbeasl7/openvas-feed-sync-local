# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100937");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_name("Exponent CMS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exponentcms.org");

  script_tag(name:"summary", value:"Detection of Exponent CMS.

  This script sends a connection request to the server and attempts
  to detect the presence of Exponent CMS and to extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/exponent", "/cms", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach page( make_list( "/index.php", "/login.php", "/index.php?controller=login&action=showlogin" ) ) {

    url = dir + page;
    buf = http_get_cache( item:url, port:port );
    if( buf == NULL ) continue;

    if( egrep( pattern:'meta name="Generator" content="Exponent', string:buf, icase:TRUE ) ||
        ( ">Exponent CMS" >< buf && "EXPONENT.LANG" >< buf ) ) {

      vers = "unknown";

      version = eregmatch( string:buf, pattern:'Exponent Content Management System - ([^"]+)', icase:TRUE );
      if( version[1] ) {
        version2 = eregmatch( string:version[1], pattern:'v([0-9.]+)' );
        if( version2 ) {
          vers = version2[1];
        } else {
          version2 = eregmatch( string:version[1], pattern:'([0-9.]+)' );
          if( version2 ) vers = version2[1];
        }
        patch = eregmatch( string: version[0], pattern:'patch([0-9]+)');
        if( patch[1] && vers != "unknown" ){
          vers += "." + patch[1];
        }
      }

      set_kb_item( name:"ExponentCMS/installed", value:TRUE );
      set_kb_item( name:"www/" + port + "/exponent", value:vers + " under " + install );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:exponentcms:exponent_cms:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:exponentcms:exponent_cms";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Exponent Content Management System",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
      exit( 0 );
    }
  }
}

exit( 0 );
