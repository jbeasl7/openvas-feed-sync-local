# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108348");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of NetEx HyperIP virtual appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

buf = http_get_cache( item:"/", port:port );

if( "<TITLE>HyperIP Home</TITLE>" >< buf ) {

  version = "unknown";

  url = "/bstatus.php";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # <span id="hyperipCurVer">6.1.1</span></td>
  vers = eregmatch( pattern:'hyperipCurVer">([0-9.]+)</span>', string:buf );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"hyperip/http/" + port + "/concluded", value:vers[0] );
    set_kb_item( name:"hyperip/http/" + port + "/concludedUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }

  set_kb_item( name:"hyperip/http/" + port + "/version", value:version );
  set_kb_item( name:"hyperip/detected", value:TRUE );
  set_kb_item( name:"hyperip/http/detected", value:TRUE );
  set_kb_item( name:"hyperip/http/port", value:port );
}


exit( 0 );
