# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105286");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-06-24T05:41:22+0000");
  script_tag(name:"last_modification", value:"2025-06-24 05:41:22 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-06-03 15:28:32 +0200 (Wed, 03 Jun 2015)");
  script_name("Barracuda Web Filter Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Barracuda Web Filter.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BarracudaHTTP/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( ! banner || "BarracudaHTTP" >!< banner )
  exit( 0 );

url = "/cgi-mod/index.cgi";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! buf || "Web Filter: Welcome" >!< buf )
  exit( 0 );

set_kb_item( name:"barracuda_web_filter/installed", value:TRUE );
cpe = "cpe:/a:barracuda:web_filter";
install = "/cgi-mod/";

version = eregmatch( pattern:'/barracuda\\.css\\?v=([0-9.]+)">', string:buf );
if( isnull( version[1] ) ) {
  url = "/cgi-mod/view_help.cgi";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf )
    version = eregmatch( pattern:'/barracuda\\.css\\?v=([0-9.]+)">', string:buf );
}

if( ! isnull( version[1] ) ) {
  vers = version[1];
  cpe += ":" + vers;
  set_kb_item( name:"barracuda_web_filter/version", value:vers );
}

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Barracuda Web Filter",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
             port:port );

exit( 0 );

