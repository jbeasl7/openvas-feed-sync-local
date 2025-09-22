# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108744");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-04-08 12:49:27 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Huawei VRP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTP based detection of Huawei Versatile Routing Platform (VRP) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url1 = "/copyright/info.js";
buf1 = http_get_cache( item:url1, port:port );

url2 = "/view/loginPro.html";
buf2 = http_get_cache( item:url2, port:port );

url3 = "/view/login.html";
buf3 = http_get_cache( item:url3, port:port );

concl1 = egrep( string:buf1, pattern:'(^Server\\s*:\\s*(HUAWEI|HuaWei|AR|WLAN)|var COPYRIGHT\\s*=\\s*\\{\\s*manufacturer\\s*:\\s*"Huawei")', icase:FALSE );
if( concl1 ) {
  concl = chomp( concl1 );
  url = url1;
  found = TRUE;
}

concl2 = egrep( string:buf2, pattern:"Log In to (WLAN|AR|Router) Web", icase:FALSE );
if( buf2 =~ "^HTTP/1\.[01] 200" && "Huawei" >< buf2 && concl2 ) {
  concl = chomp( concl2 );
  concl = ereg_replace( string:concl, pattern:'[\r\n]', replace:"<newline>" );
  concl = ereg_replace( string:concl, pattern:"^ +", replace:"" );
  url = url2;
  found = TRUE;
}

concl3 = egrep( string:buf3, pattern:"Log In to (WLAN|AR|Router) Web", icase:FALSE );
if( buf3 =~ "^HTTP/1\.[01] 200" && "Huawei" >< buf3 && concl3 ) {
  concl = chomp( concl3 );
  concl = ereg_replace( string:concl, pattern:'[\r\n]', replace:"<newline>" );
  concl = ereg_replace( string:concl, pattern:"^ +", replace:"" );
  url = url3;
  found = TRUE;
}

if( found ) {

  version = "unknown";
  model   = "unknown";

  # Server: HUAWEI
  # Server: HuaWei-S6720-EI
  #
  # This should be excluded (currently unknown devices):
  # Server: Huawei-BMC
  # Server: HUAWEI-2.11
  # Server: Huawei API-Gateway 1.0
  # Server: HUAWEI-CT03
  # Server: HUAWEI-VINGADORES
  # Server: HUAWEI S5720S-waiwang-2
  mod = eregmatch( string:concl, pattern:'Server\\s*:\\s*HuaWei-([^\r\n]+)', icase:FALSE );
  if( mod[1] )
    model = mod[1];

  set_kb_item( name:"huawei/vrp/detected", value:TRUE );
  set_kb_item( name:"huawei/vrp/http/detected", value:TRUE );
  set_kb_item( name:"huawei/vrp/http/port", value:port );

  set_kb_item( name:"huawei/vrp/http/" + port + "/model", value:model );
  set_kb_item( name:"huawei/vrp/http/" + port + "/version", value:version );
  set_kb_item( name:"huawei/vrp/http/" + port + "/concluded", value:concl );
  set_kb_item( name:"huawei/vrp/http/" + port + "/concluded_location", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
}

exit( 0 );
