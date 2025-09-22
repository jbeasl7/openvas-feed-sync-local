# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805964");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-08-26 15:48:59 +0530 (Wed, 26 Aug 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Netsweeper Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Netsweeper.

  This script performs a HTTP based detection of Netsweeper.");

  script_xref(name:"URL", value:"https://www.netsweeper.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:443);

if( ! http_can_host_php( port:port ) )
  exit( 0 );

url = "/webadmin/start/index.php";

res = http_get_cache( port:port, item:url );

if( egrep( pattern:">Netsweeper WebAdmin", string:res, icase:TRUE ) && "Set-Cookie: webadmin" >< res ) {
  install = "/";
  version = "unknown";

  # See https://github.com/rapid7/metasploit-framework/pull/13429/files#diff-74625bfeb3198f642a56954729cb9b91R152
  # for whitelisted referrers
  url = "/webadmin/tools/systemstatus_remote.php";
  headers = make_list( "Content-Type", "application/x-www-form-urlencoded" );
  referer = "webadmin/admin/systemstatus_inc_data.php";

  req = http_get_req( port:port, url:url, add_headers:headers, referer_url:referer );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # Wed, 13 May 2020 00:05:46 -0400
  # Version: 6.4.3
  # Database Version: 139
  vers = eregmatch( pattern:"Version: ([0-9.]+)", string:res );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  set_kb_item( name:"netsweeper/detected", value:TRUE );

  # Netsweeper runs on CentOS
  os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", desc:"Netsweeper Detection (HTTP)",
                          runs_key:"unixoide" );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:netsweeper:netsweeper:" );
  if( ! cpe )
    cpe = "cpe:/a:netsweeper:netsweeper";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Netsweeper", version:version, install:install, cpe:cpe,
                                            concluded:vers[0], concludedUrl:conclUrl ),
               port:port );
}

exit( 0 );
