# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105590");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-03-30 13:30:23 +0200 (Wed, 30 Mar 2016)");
  script_name("Basho Riak Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Basho Riak.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8098);
  script_mandatory_keys("MochiWeb/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8098 );

banner = http_get_remote_headers( port:port );
if( "MochiWeb" >!< banner ) exit( 0 );

url = "/stats";
buf = http_get_cache( item:url, port:port );

if( buf !~ "^HTTP/1\.[01] 200" || "riak_search_version" >!< buf ) exit( 0 );

b = split( buf, sep:'\r\n\r\n', keep:FALSE );
if( ! b[1] ) exit( 0 );

values = split( b[1], sep:",", keep:FALSE );

foreach v ( values )
{
  if( "riak_search_version" >< v )
  {
    version = eregmatch( pattern:'"riak_search_version":"([^"]+)"', string:v );
    if( ! isnull( version[1] ) ) vers = version[1];
  }

  val_rep += v + '\n';
}

cpe = "cpe:/a:basho:riak";

if( vers ) # for example 1.4.7-0-g2a44e2f while gb_riak_detect.nasl will report just 1.4.7.
  cpe += ":" + vers;
else
  vers = "unknown";

register_product( cpe:cpe, location:"/", port:port, service:"www" );
set_kb_item( name:"riad/http/stats", value:val_rep );
set_kb_item( name:"riad/installed", value:TRUE );

report = build_detection_report( app:"Basho Riak", version:vers, install: "/",concluded:version[0], cpe:cpe, extra:'\nStats:' + val_rep + '\n' );

log_message( port:port, data:report );
exit( 0 );
