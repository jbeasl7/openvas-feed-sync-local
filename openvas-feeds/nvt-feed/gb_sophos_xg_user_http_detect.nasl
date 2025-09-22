# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105626");
  script_version("2022-11-16T10:12:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-16 10:12:35 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"creation_date", value:"2016-04-27 12:37:42 +0200 (Wed, 27 Apr 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sophos XG Firewall Detection (HTTP, User Portal)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of a Sophos XG Firewall from the user
  portal.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/userportal/webpages/myaccount/login.jsp";
res = http_get_cache( item:url, port:port );
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

if( ! found = eregmatch( string:res, pattern:"<title>(User Portal|Sophos)</title>", icase:FALSE ) )
  exit( 0 );

concl = "    " + found[0];

if( ! found = eregmatch( string:res, pattern:'Cyberoam\\.setContextPath\\("/userportal"\\)', icase:FALSE ) )
  exit( 0 );

concl += '\n    ' + found[0];

url1 = "/javascript/lang/English/common.js";
req1 = http_get( item:url1, port:port );
# nb: Don't use http_get_cache() or http_keepalive_send_recv() as the latter (internally used by
# http_get_cache() seems to have some problems receiving the large .js file from time to time.
res1 = http_send_recv( data:req1, port:port );

# Sophos Central",firewall
if( ! res1 || ! found = eregmatch( string:res1, pattern:"([Ss]ophos [^ ]*[Ff]irewall|Cyberroam)", icase:FALSE ) )
  exit( 0 );

concl += '\n    ' + found[0];
conclUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
conclUrl += '\n    ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );

set_kb_item( name:"sophos/xg_firewall/detected", value:TRUE );
set_kb_item( name:"sophos/xg_firewall/http-user/detected", value:TRUE );
set_kb_item( name:"sophos/xg_firewall/http-user/port", value:port );

version = "unknown";

# Examples:
#
# ver=17.5.10.620 (620 seems to be the "build")
#
# <link href="/themes/lite1/css/typography.css?version=17.5.13.692" rel="stylesheet" type="text/css" />
# <link rel="stylesheet" href="/themes/lite1/css/loginstylesheet.css?ver=17.5.13.692" type="text/css">
# <LINK REL="ICON" HREF="/images/favicon.ico?ver=17.5.13.692">
# <script type="text/javascript" src="/javascript/validation/JavaConstants.js?ver=17.5.13.692"></script>
# <script type="text/javascript" src="/javascript/validation/OEM.js?ver=17.5.13.692"></script>
# <script type="text/javascript" src="/javascript/validation/login.js?ver=17.5.13.692"></script>
#
# nb: At least since release 18 the version is not included anymore.
vers = eregmatch( pattern:'ver=([0-9]+\\.[^"\' ]+)', string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  concl += '\n    ' + vers[0];
}

set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/concluded", value:concl );
set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/concludedUrl", value:conclUrl );
set_kb_item( name:"sophos/xg_firewall/http-user/" + port + "/version", value:version );

exit( 0 );
