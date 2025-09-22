# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800683");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNN / DotNetNuke Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DNN (formerly DotNetNuke).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# nb:
# - DotNetNuke is nowaday just called "DNN"
# - Product can be detected, but version detection requires authentication for newer versions

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/dotnetduke", "/dnnarticle", "/cms", "/DotNetNuke", "/DotNetNuke Website", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  found = FALSE;
  conclUrl = NULL;

  url = dir + "/default.aspx";
  res = http_get_cache( item:url, port:port );
  url2 = dir + "/Install/InstallWizard.aspx";
  res2 = http_get_cache( item:url2, port:port );
  url3 = dir + "/DesktopModules/AuthenticationServices/OpenID/license.txt";
  res3 = http_get_cache( item:url3, port:port );
  url4 = dir + "/";
  res4 = http_get_cache( item:url4, port:port );

  if( res2 =~ "^HTTP/1\.[01] 200" && "DotNetNuke Installation Wizard" >< res2 ) {
    found = TRUE;
    conclUrl = "  " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( res3 =~ "^HTTP/1\.[01] 200" && "DotNetNuke" >< res3 && "www.dotnetnuke.com" >< res3 ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( res4 =~ "^HTTP/1\.[01] 200" &&
      ( ( "DotNetNuke" >< res4 || "DnnModule" >< res4 ) &&
        ( "DesktopModules" >< res4 || "dnnVariable" >< res4 || "www.dotnetnuke.com" >< res4 ||
          "DNN_HTML" >< res4 || "DotNetNukeAnonymous" >< res4 )
      ) ||
      ( res4 =~ 'id="dnn_' && res4 =~ 'class="DnnModule' )
    ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url4, url_only:TRUE );
  }

  if( res =~ "^HTTP/1\.[01] 200" &&
      ( ( "DotNetNuke" >< res || "DnnModule" >< res ) &&
        ( "DesktopModules" >< res || "dnnVariable" >< res || "www.dotnetnuke.com" >< res ||
          "DNN_HTML" >< res || "DotNetNukeAnonymous" >< res )
      ) ||
      ( res =~ 'id="dnn_' && res =~ 'class="DnnModule' )
    ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  if( found ) {
    version = "unknown";

    # >Welcome to DNN 6.0<
    vers = eregmatch( pattern:"(Welcome to )?DNN ([0-9.]{3,})", string:res, icase:FALSE );
    if( vers[2] )
      version = vers[2];

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"(Welcome to )?DNN ([0-9.]{3,})", string:res4, icase:FALSE );
      if( vers[2] )
        version = vers[2];
    }

    set_kb_item( name:"dotnetnuke/detected", value:TRUE );
    set_kb_item( name:"dotnetnuke/http/detected", value:TRUE );
    set_kb_item( name:"dotnetnuke/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
  }
}

exit( 0 );
