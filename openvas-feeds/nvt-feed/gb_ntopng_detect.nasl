# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107109");
  script_version("2021-05-10T06:48:45+0000");
  script_tag(name:"last_modification", value:"2021-05-10 06:48:45 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2016-12-20 06:40:16 +0200 (Tue, 20 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ntopng Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ntopng.");

  script_xref(name:"URL", value:"https://www.ntop.org/products/traffic-analysis/ntop/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:3000 );

url = "/lua/about.lua";

req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req ); # nb: Use http_send_recv as some older versions have issues when sending a keepalive request

version = "unknown";

if( "<title>Welcome to ntopng</title>" >< res && "<h2>About ntopng</h2>" >< res ) {
  found = TRUE;
  # e.g. <tr><th>Version</th><td>1.0.1 (r6777)</td></tr>
  vers = eregmatch( string:res, pattern:"<th>Version</th><td>([0-9\.]+)( \(r([0-9]+)\))?", icase:TRUE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    if( ! isnull( vers[3] ) )
      extra = "Revision: " + vers[3];
  }
}

if( ! found ) {
  url = "/lua/login.lua?referer=/";

  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req ); # nb: Use http_send_recv as some older versions have issues when sending a keepalive request

  if( "erver: ntopng" >< res || "<title>Welcome to ntopng</title>" >< res ||
      "ntop.org<br> ntopng is released under" >< res ) {
    found = TRUE;
    vers = eregmatch( string:res, pattern:"Server: ntopng ([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1];
  }
}

if( found ) {
  set_kb_item( name:"ntopng/detected", value:TRUE );
  set_kb_item( name:"ntopng/http/detected", value:TRUE );

  concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntopng:" );
  if( ! cpe )
    cpe = "cpe:/a:ntop:ntopng";

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data:build_detection_report( app:"ntopng", version:version, install:"/", cpe:cpe,
                                            concluded:vers[0], concludedUrl:concUrl, extra:extra ),
               port:port );
  exit( 0 );
}

exit( 0 );
