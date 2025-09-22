# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140184");
  script_version("2025-01-07T06:11:07+0000");
  script_tag(name:"last_modification", value:"2025-01-07 06:11:07 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-03-14 14:06:33 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dahua Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dahua Devices (DVR/NVR/IPC) and their
  OEMs.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
# nb: The devices doesn't provide a "Server:" banner. This check should prevent some possible
# false detection for other unrelated devices / vendors.
if( ! banner || egrep( string:banner, pattern:"^Server\s*:.+", icase:TRUE ) )
  exit( 0 );

buf = http_get_cache( port:port, item:"/" );

if( ( "<title>WEB SERVICE</title>" >< buf && "ui-dialog-content" >< buf ) ||
    ( "@WebVersion@" >< buf && ( "t_username" >< buf && ">Login<" >< buf ) || "com.ErrorAuthorizeReloginTip" >< buf ) ||
    ( "ui-video-wrap-icon" >< buf && "t_username" >< buf && "slct_userType" >< buf ) ||
    ( '"method":"global.login"' >< buf && "/RPC2_Login" >< buf ) ) {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url( port:port, url:location, url_only:TRUE );

  set_kb_item( name:"dahua/device/detected", value:TRUE );
  set_kb_item( name:"dahua/device/http/detected", value:TRUE );

  os_register_and_report( os:"Linux/Unix (Embedded)", cpe:"cpe:/o:linux:kernel",
                          banner_type:"Dahua Web Service", port:port, desc:"Dahua Devices Detection (HTTP)",
                          runs_key:"unixoide" );

  cpe = "cpe:/a:dahua:nvr";

  register_product( cpe:cpe, location:location, port:port, service:"www" );

  log_message( data:build_detection_report( app: "Dahua Web Service", version:version, install:location,
                                            cpe:cpe, concludedUrl:conclUrl ),
               port:port );
  exit( 0 );
}

exit( 0 );
