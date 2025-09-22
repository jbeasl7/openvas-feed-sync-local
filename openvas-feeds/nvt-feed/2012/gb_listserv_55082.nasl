# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103545");
  script_version("2022-12-08T10:12:32+0000");
  script_tag(name:"last_modification", value:"2022-12-08 10:12:32 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-08-20 10:41:31 +0200 (Mon, 20 Aug 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LISTSERV <= 16 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"LISTSERV is prone to a cross-site scripting (XSS) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"LISTSERV version 16 and probably prior.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55082");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/cgi-bin/listserv", "/listserv", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache(port: port, item: dir + "/wa.exe");
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/wa.exe?SHOWTPL=<script>alert(/xss-test/)</script>";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE,
                       extra_check:"template could not be found" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
