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

CPE = "cpe:/a:ntop:ntopng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108032");
  script_version("2021-12-17T12:28:02+0000");
  script_tag(name:"last_modification", value:"2021-12-17 12:28:02 +0000 (Fri, 17 Dec 2021)");
  script_tag(name:"creation_date", value:"2016-12-26 17:00:00 +0100 (Mon, 26 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ntopng Default Admin Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_ntopng_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ntopng/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"This script detects default admin credentials for ntopng via
  HTTP.");

  script_tag(name:"vuldetect", value:"Check if it is possible to login with default admin
  credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"insight", value:"It was possible to login with default credentials
  'admin:admin'.");

  script_tag(name:"solution", value:"Change the password of the 'admin' account.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/authorize.html";

data = "user=admin&password=admin&referer=/";

req = http_post_put_req( port:port, url:url, data:data,
                         accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );

cookie = eregmatch( pattern:"Set-Cookie: (session=[A-Za-z0-9;]+)", string:res );
if( isnull( cookie[1] ) )
  exit( 0 );

cookie = cookie[1] + " user=admin";

url = dir + "/lua/pro/dashboard.lua";

req = http_get_req( url:url, port:port,
                    accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    add_headers:make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && ( 'placeholder="Search Host"' >< res || '<form action="/lua/host_details.lua">' >< res ) ) {
  report = "It was possible to login to the URL " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + " with the default credentials 'admin:admin'.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
