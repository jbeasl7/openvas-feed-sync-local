# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103918");
  script_version("2023-12-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-12-22 05:05:24 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-03-13 10:13:17 +0100 (Thu, 13 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("JFrog Artifactory Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of JFrog Artifactory.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://jfrog.com/artifactory/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/artifactory", http_cgi_dirs( port:port ) ) ) {

  detected = FALSE;
  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: Version service on older JFrog Artifactory versions
  url1 = dir + "/ui/auth/screen/footer";
  buf1 = http_get_cache( port:port, item:url1 );

  # nb: Version service on newer JFrog Artifactory versions
  url2 = dir + "/ui/api/v1/ui/auth/loginRelatedData";
  buf2 = http_get_cache( port:port, item:url2 );

  # nb: Legacy detection of JFrog Artifactory versions
  url3 = dir + "/webapp/home.html?0";
  buf3 = http_get_cache( port:port, item:url3 );

  if( "Artifactory OSS" >< buf1 && buf1 =~ "HTTP/1\.[01] 200" ) {
    detected = TRUE;
    concludedUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
  }

  if( buf2 =~ "X-Jfrog-Version: Artifactory/([0-9.]+) ([0-9]+)" ) {
    detected = TRUE;
    concludedUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( "Artifactory is happily serving" >< buf3 && "<title>Artifactory" >< buf3 ) {
    detected = TRUE;
    concludedUrl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( detected ) {
    version = "unknown";

    vers = eregmatch( string:buf1, pattern:'"buildNumber":"([0-9.]+) rev ([0-9]+)"', icase:TRUE );
    if( isnull( vers[1] ) )
      vers = eregmatch( string:buf1, pattern:"Server: Artifactory/([0-9.]+)", icase:TRUE );
    if( isnull( vers[1] ) )
      vers = eregmatch( string:buf2, pattern:"X-Jfrog-Version: Artifactory/([0-9.]+) ([0-9]+)", icase:TRUE );
    if( isnull( vers[1] ) )
      vers = eregmatch( string:buf3, pattern:'<span class="version">Artifactory ([0-9.]+)', icase:TRUE );

    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"jfrog/artifactory/detected", value:TRUE );
    set_kb_item( name:"jfrog/artifactory/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:jfrog:artifactory:" );
    if( ! cpe )
      cpe = "cpe:/a:jfrog:artifactory";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"JFrog Artifactory", version:version, install:install,
                                               cpe:cpe, concludedUrl:concludedUrl, concluded:vers[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
