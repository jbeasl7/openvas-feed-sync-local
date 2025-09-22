# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100313");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AfterLogic WebMail Pro Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running AfterLogic WebMail Pro, a Webmail front-end for your
  existing POP3/IMAP mail server.");

  script_xref(name:"URL", value:"http://www.afterlogic.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( http_can_host_asp( port:port ) && http_can_host_php( port:port ) ) {
  files = make_list( "/index.php", "/default.aspx" );
} else if( http_can_host_asp( port:port ) ) {
  files = make_list( "/default.aspx" );
} else if( http_can_host_php( port:port ) ) {
  files = make_list( "/index.php" );
} else {
  exit( 0 );
}

foreach dir( make_list_unique( "/webmail", "/mail", "/email", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file;
    buf = http_get_cache( item:url, port:port );
    if( !buf ) continue;

    if( egrep( pattern:"Powered by.*AfterLogic WebMail Pro", string:buf, icase:TRUE ) ) {

      vers = "unknown";
      version = eregmatch( string:buf, pattern:"<!--[^0-9]*([0-9.]+)[^-]*-->", icase:TRUE );
      if( ! isnull( version[1] ) )
        vers = chomp( version[1] );

      set_kb_item( name:"AfterLogicWebMailPro/installed", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:afterlogic:mailbee_webmail_pro:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:afterlogic:mailbee_webmail_pro";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"AfterLogic WebMail Pro",
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
