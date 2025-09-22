# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800371");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_name("Apache Tomcat Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Tomcat.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

# nb: For /tomcat-docs/changelog.html
verPattern = "<strong>Tomcat ([0-9.]+)([.-](RC|M)([0-9.]+))?";
# nb: For other files, this should match e.g.:
# - index.jsp:
#   <title>Apache Tomcat/9.0.20</title>
#   <h1>Apache Tomcat/9.0.20</h1>
#   <title>Apache Tomcat/9.0.0.M1</title>
#   <h1>Apache Tomcat/9.0.0.M1</h1>
# - RELEASE-NOTES.txt:
#   Apache Tomcat Version 9.0.22
#   Apache Tomcat Version 6.0.20
# - On error / 404 pages:
#   <title>Apache Tomcat/9.0.0.M1 - Error report</title>
#   <h3>Apache Tomcat/9.0.0.M1</h3>
#   <h3>Apache Tomcat/@VERSION@</h3>
#   <h3>Apache Tomcat/9.0.20</h3>
#   <h3>Apache Tomcat/8.5.50</h3>
# - Generally in the header (only for older versions, some might be Honeypots):
#   Server: Apache Tomcat/4.1.10
#   X-Powered-By: Apache Tomcat/7.0.11
verPattern2 = "Apache Tomcat( Version |\/)([0-9.]+)([-.](RC|M)([0-9.]+))?";
conclPattern = '(Apache Tomcat|Tomcat (Host )?Manager Application)[^\r\n]+';

port = http_get_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

identified = FALSE;
verFound = FALSE;
conclUrl = ""; # nb: To make openvas-nasl-lint happy...
_conclUrl = "";

# nb: index.jsp sometimes consists of a version that can be misidentified, such as "Apache Tomcat/7.0.x", so we put it at the last possible position
foreach file( make_list( "/tomcat-docs/changelog.html", "/docs/changelog.html", "/RELEASE-NOTES.txt", "/docs/RELEASE-NOTES.txt", "/index.jsp" ) ) {

  res = http_get_cache( item:file, port:port );

  if( res =~ "^HTTP/1\.[01] 200" && "Apache Tomcat" >< res ) {
    _concluded = eregmatch( string:res, pattern:conclPattern, icase:FALSE );
    if( _concluded )
      concluded = _concluded[0];
    identified = TRUE;
  }

  # The 404 error page is checked later. Continue here to avoid that we're matching against a wrong pattern
  if( res =~ "^HTTP/1\.[01] 404" )
    continue;

  if( egrep( pattern:verPattern, string:res ) || egrep( pattern:verPattern2, string:res ) ) {
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += http_report_vuln_url( port:port, url:file, url_only:TRUE );
    verFound = TRUE;
    break;
  }
}

if( ! verFound ) {

  foreach file( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

    res = http_get_cache( item:file, port:port, fetch404:TRUE );
    if( res =~ "^HTTP/1\.[01] 404" && "Apache Tomcat" >< res ) {
      _concluded = eregmatch( string:res, pattern:conclPattern, icase:FALSE );
      if( _concluded )
        concluded = _concluded[0];
      identified = TRUE;
      # nb: Used if the version is hidden on the error page (e.g. <h3>Apache Tomcat/@VERSION@</h3>)
      if( _conclUrl )
        _conclUrl += '\n';
      _conclUrl = http_report_vuln_url( port:port, url:file, url_only:TRUE );
    }

    if( egrep( pattern:verPattern2, string:res ) ) {
      if( conclUrl )
        conclUrl += '\n';
      conclUrl += http_report_vuln_url( port:port, url:file, url_only:TRUE );
      verFound = TRUE;
      break;
    }
  }
  if( identified && ! conclUrl )
    conclUrl += _conclUrl;
}

if( ! verFound ) {

  # nb: This should trigger a "HTTP Status 400 - Bad Request" containing something like e.g.:
  # > The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid request message framing, or deceptive request routing).
  foreach file( make_list( "/[", "/vt-test/[" ) ) {

    res = http_get_cache( item:file, port:port, fetch404:TRUE );

    if( res =~ "^HTTP/1\.[01] 400" && "<h3>Apache Tomcat" >< res ) {
      _concluded = eregmatch( string:res, pattern:conclPattern, icase:FALSE );
      if( _concluded )
        concluded = _concluded[0];
      identified = TRUE;
      if( _conclUrl )
        _conclUrl += '\n';
      _conclUrl = http_report_vuln_url( port:port, url:file, url_only:TRUE );
    }

    if( egrep( pattern:verPattern2, string:res ) ) {
      if( conclUrl )
        conclUrl += '\n';
      conclUrl += http_report_vuln_url( port:port, url:file, url_only:TRUE );
      verFound = TRUE;
      break;
    }
  }
  if( identified && ! conclUrl )
    conclUrl += _conclUrl;
}

authDirs = http_get_kb_auth_required( port:port, host:host );
if( authDirs ) {

  # Sort to not report changes on delta reports if just the order is different
  authDirs = sort( authDirs );

  foreach url( authDirs ) {

    # nb: We're only interested in previously found URLs including "manager/"
    if( "manager/" >!< url )
      continue;

    authReq = http_get( item:url, port:port );
    authRes = http_keepalive_send_recv( port:port, data:authReq, bodyonly:FALSE );

    if( authRes =~ "^HTTP/1\.[01] 401" ) {
      if( "Tomcat Manager Application" >< authRes || "Tomcat Host Manager Application" >< authRes ||
          "Tomcat Manager Application" >< authRes ) {
        _concluded = eregmatch( string:authRes, pattern:conclPattern, icase:FALSE );
        if( _concluded )
          concluded = _concluded[0];

        set_kb_item( name:"www/" + host + "/" + port + "/ApacheTomcat/auth_required", value:url );
        set_kb_item( name:"ApacheTomcat/auth_required", value:TRUE );
        identified = TRUE;
        if( conclUrl )
          conclUrl += '\n';
        conclUrl += http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }
}

if( identified ) {

  vers = "unknown";
  install = port + "/tcp";

  # nb:
  # - To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
  #   supporting these
  # - External resources seems to indicate that Tomcat supports both (either directly or via some
  #   external integration or if used as some kind of proxy)
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"yes" );

  version = eregmatch( pattern:verPattern, string:res );

  if( "<strong>Tomcat" >< version[0] && ! isnull( version[1] ) ) {
    vers = version[1];
    if( version[2] ) {
      version[2] = ereg_replace( pattern:"-", string:version[2], replace: "." );
      vers = version[1] + version[2];
      concluded = version[0];
    }
  }

  else {

    version = eregmatch( pattern:verPattern2, string:res );

    if( "Apache Tomcat" >< version[0] && ! isnull( version[2] ) ) {
      concluded = version[0];
      vers = version[2];
      if( version[3] ) {
        version[3] = ereg_replace( pattern:"-", string:version[3], replace: "." );
        vers = version[2] + version[3];
      }
    }
  }

  set_kb_item( name:"apache/tomcat/detected", value:TRUE );
  set_kb_item( name:"apache/tomcat/http/detected", value:TRUE );
  set_kb_item( name:"apache/tomcat/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + vers + "#---#" + concluded + "#---#" + conclUrl );
}

exit( 0 );
