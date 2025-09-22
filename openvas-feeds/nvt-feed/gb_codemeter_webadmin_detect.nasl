# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801988");
  script_version("2025-06-20T15:42:07+0000");
  script_tag(name:"last_modification", value:"2025-06-20 15:42:07 +0000 (Fri, 20 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WIBU-SYSTEMS CodeMeter WebAdmin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 22350, 22352, 22353);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of WIBU-SYSTEMS CodeMeter WebAdmin.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

function report_runtime( port, url, location, version, concluded ) {

  local_var port, url, location, version;
  local_var concluded;

  concluded = http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n  ' + concluded;
  set_kb_item( name:"wibu/codemeter_runtime/detected", value:TRUE );
  set_kb_item( name:"wibu/codemeter_runtime/http/port", value:port );
  set_kb_item( name:"wibu/codemeter_runtime/http/" + port + "/detected", value:TRUE );
  set_kb_item( name:"wibu/codemeter_runtime/http/" + port + "/location", value:location );
  set_kb_item( name:"wibu/codemeter_runtime/http/" + port + "/version", value:version );
  set_kb_item( name:"wibu/codemeter_runtime/http/" + port + "/concluded", value:concluded );
}

# Description of the ports:
# 22350 -> Default of older WebAdmin versions, newer ones are redirecting to 22352
# 22352 -> Default of newer WebAdmin versions
# 22353 -> Default if HTTPS is enabled. 22352 redirects to this port.
ports = http_get_ports( default_port_list:make_list( 22350, 22352, 22353 ) );
foreach port( ports ) {

  banner = http_get_remote_headers( port:port );

  url = "/home.html";
  res = http_get_cache( item:url, port:port );

  url2 = "/index.html";
  res2 = http_get_cache( item:url2, port:port );

  url3 = "/dashboard.html";
  res3 = http_get_cache( item:url3, port:port );

  if( "<title>CodeMeter | WebAdmin</title>" >< res ||
      "WIBU-SYSTEMS HTML Served Page" >< res ||
      "<title>CodeMeter | WebAdmin</title>" >< res2 ||
      "WIBU-SYSTEMS HTML Served Page" >< res2 ||
      ( ">WebAdmin | " >< res3 && "WIBU-SYSTEMS" >< res3 ) ||
      ">The access to the CodeMeter Server was not permitted<" >< res3 ||
      "Server: WIBU-SYSTEMS HTTP Server" >< banner ) {

    version = "unknown";
    install = "/";
    conclUrl = "";

    # Older versions on home.html (res)
    ver = eregmatch( pattern:"WebAdmin Version[^\n]+Version ([0-9.]+)", string:res );
    if( ver[1] ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    # Newer versions on index.html (res2)
    if( version == "unknown" ) {
      # <p><span class="t-webadmin-version">WebAdmin Version</span>: <span class="bld">6.40</span></p>
      # <p><span class="t-webadmin-version">WebAdmin Version</span>: <span class="bld">6.50</span></p>
      ver = eregmatch( pattern:'>WebAdmin Version[^\n]+>([0-9.]+)<', string:res2 );
      if( ver[1] ) {
        version = ver[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    # nb: report_runtime also sets keys for VT 'WIBU CodeMeter Runtime Detection Consolidation' OID: 1.3.6.1.4.1.25623.1.0.107791
    runtime_vers = eregmatch( pattern:'>Runtime Version[^\n]+\n[^\n]+(([0-9.]+)([a-z]+)?)<', string:res2 );
    if( runtime_vers[1] ) {
      report_runtime( port:port, url:url2, location:install, version:runtime_vers[1], concluded:runtime_vers[0] );
    } else {
      runtime_vers = eregmatch( pattern:'>Runtime Version[^\n]+\n[^\n]+>(([0-9.]+)([a-z]+)?)<', string:res3 );
      if( runtime_vers[1] )
        report_runtime( port:port, url:url3, location:install, version:runtime_vers[1], concluded:runtime_vers[0] );
    }

    # Newer versions on dashboard.html (res3)
    if( version == "unknown" ) {
      # <span class="t-webadmin-version">WebAdmin Version</span>: <span class="bld">6.81</span>
      ver = eregmatch( pattern:'>WebAdmin Version[^\n]+>([0-9.]+)<', string:res3 );
      if( ver[1] ) {
        version = ver[1];
        conclUrl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
      }
    }

    set_kb_item( name:"wibu/codemeter_webadmin/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:wibu:codemeter_webadmin:" );
    if( ! cpe )
      cpe = "cpe:/a:wibu:codemeter_webadmin";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"WIBU-SYSTEMS CodeMeter WebAdmin",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
