# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800677");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Roller Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Roller.");

  script_add_preference(name:"Apache Roller Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Apache Roller Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://roller.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

files = make_list( "/login.rol", "/index.jsp" );

foreach dir( make_list_unique( "/roller", "/roller-ui", "/roller/roller-ui", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  foreach file( files ) {

    url = dir + file;

    res = http_get_cache( port:port, item:url );

    if( res =~ "^HTTP/1\.[01] 200" &&
        ( "Welcome to Roller" >< res || res =~ "Platform based on <[^>]+Roller" ) ) {

      version = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # >Apache Roller Weblogger</a> Version 5.0.3 (r1554688)
      vers = eregmatch( pattern:"</a> Version ([0-9.]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
      } else {
        user = script_get_preference( "Apache Roller Web UI Username", id:1 );
        pass = script_get_preference( "Apache Roller Web UI Password", id:2 );

        if( ! user && ! pass ) {
          extra += '\n  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.';
        } else if ( ! user && pass ) {
          extra += '\n  Note: Password for web authentication was provided but username is missing. Please provide both.';
        } else if ( user && ! pass ) {
          extra += '\n  Note: Username for web authentication was provided but password is missing. Please provide both.';
        } else if ( user && pass ) {
          url = dir + "/roller_j_security_check";

          headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

          data = "j_username=" + user + "&j_password=" + pass + "&login=";

          req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
          res = http_keepalive_send_recv( port:port, data:req );

          cookie = http_get_cookie_from_header( buf:res, pattern:"(JSESSIONID=[^;]+)" );
          if( isnull( cookie ) || "login.rol?error=true" >< res ) {
            extra += '\n  Note: Username and password were provided but authentication failed.';
          } else {
            url = dir + "/roller-ui/menu.rol";

            headers = make_array( "Cookie", cookie );

            req = http_get_req( port:port, url:url, add_headers:headers );
            res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

            # >Apache Roller Weblogger</a> Version 6.1.4 (rfaafe379e353dc6a44d350734e4d8113d666a3be)
            vers = eregmatch( pattern:">\s*Version\s+([0-9.]+)", string:res );
            if( ! isnull( vers[1] ) ) {
              version = vers[1];
              conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
            }
          }
        }
      }

      set_kb_item( name:"apache/roller/detected", value:TRUE );
      set_kb_item( name:"apache/roller/http/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:roller:" );
      if( ! cpe )
        cpe = "cpe:/a:apache:roller";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Apache Roller",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:vers[0],
                                                concludedUrl:conclUrl,
                                                extra:extra ),
                   port:port );
      exit( 0 );
    }
  }
}

exit( 0 );
