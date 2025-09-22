# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100190");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Eclipse GlassFish Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Eclipse GlassFish.");

  script_xref(name:"URL", value:"https://glassfish.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

host = http_host_name( dont_add_port:TRUE );

url1 = "/index.html";
url2 = "/vt-test-non-existent.html";

res = http_get_cache( port:port, item:url1 );
res2 = http_get_cache( port:port, item:url2, fetch404:TRUE );

if( ( "<title>GlassFish Server" >< res && "Server Running</title>" >< res ) ||
      egrep( pattern: "Server\s*:.*GlassFish.*", string: res, icase: TRUE ) ||
      ( "<title>GlassFish Server" >< res2 && "Error report</title>" >< res2  ) ||
      "Log In to GlassFish Administration Console" >< res ||
      egrep( pattern: "Server\s*:.*GlassFish.*", string: res2, icase: TRUE )) {

  # nb: For JavaServer Faces active checks (See "login.jsf" below)
  set_kb_item( name:"www/javaserver_faces/detected", value:TRUE );
  set_kb_item( name:"www/javaserver_faces/" + host + "/" + port + "/detected", value:TRUE );

  version = "unknown";
  location = "/";

  # Banner:
  # X-Powered-By: Servlet/3.0 JSP/2.2 (GlassFish Server Open Source Edition 3.1.2.2 Java/Oracle Corporation/1.7)
  # Server: GlassFish Server Open Source Edition 3.1.2.2
  # Server: GlassFish Server Open Source Edition  4.1
  # X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.1  Java/Oracle Corporation/1.7)
  # Sun GlassFish Enterprise Server v2.1
  # Server: Eclipse GlassFish 7.0.16

  vers = eregmatch( string:res, pattern:"Server\s*:.*GlassFish[^0-9]+v([0-9.]+)", icase:TRUE );
  if( isnull( vers[1] ) ) {
    vers = eregmatch( string:res, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[3] ) ) {
      version = vers[3];
      conclUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
    } else {
      vers = eregmatch( string:res2, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)",
                        icase:TRUE );
      if( ! isnull( vers[3] ) ) {
        version = vers[3];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      } else {
        vers = eregmatch( string:res2, pattern:"Server\s*:.*GlassFish.*v([0-9.]+)", icase:TRUE );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        } else {
          vers = eregmatch( string:res2, pattern:"Eclipse GlassFish ([0-9.]+)" );
          if( ! isnull( vers[1] ) ) {
            version = vers[1];
            conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
          }
        }
      }
    }
  } else {
    version = vers[1];
    conclUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
  }

  if( egrep( pattern:"Location:.*login.jsf", string:res ) ||
      ( egrep( pattern:"Log In to.*GlassFish", string:res ) && "<title>Login" >< res ) ) {

    extra = "The GlassFish Administration Console is running at this port.";
    set_kb_item( name:"www/" + port + "/GlassFishAdminConsole", value:TRUE );
    set_kb_item( name:"GlassFishAdminConsole/port", value:port );
  }

  set_kb_item( name:"eclipse/glassfish/detected", value:TRUE );
  set_kb_item( name:"eclipse/glassfish/http/detected", value:TRUE );
  set_kb_item( name:"glassfish_or_sun_java_appserver/installed", value:TRUE );

  cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:eclipse:glassfish:");
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:oracle:glassfish_server:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:eclipse:glassfish";
    cpe2 = "cpe:/a:oracle:glassfish_server";
  }

  register_product( cpe:cpe1, location:location, port:port, service:"www" );
  register_product( cpe:cpe2, location:location, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Eclipse GlassFish", version:version, install:location,
                                            cpe:cpe1, concluded:vers[0], concludedUrl: conclUrl,
                                            extra:extra ),
               port:port );
  exit( 0 );
}

exit( 0 );
