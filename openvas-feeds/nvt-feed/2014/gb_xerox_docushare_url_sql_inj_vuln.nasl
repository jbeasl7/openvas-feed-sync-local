# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:fujixerox:docushare";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804556");
  script_version("2022-09-07T10:10:59+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-04-24 15:12:51 +0530 (Thu, 24 Apr 2014)");
  script_cve_id("CVE-2014-3138");
  script_name("Xerox DocuShare SQLi Vulnerability (Apr 2014)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xerox_docushare_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("xerox/docushare/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57996");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66922");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32886");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126171");
  script_xref(name:"URL", value:"https://gist.github.com/brandonprry/10745681");
  script_xref(name:"URL", value:"http://www.xerox.com/download/security/security-bulletin/a72cd-4f7a54ce14460/cert_XRX14-003_V1.0.pdf");

  script_tag(name:"summary", value:"Xerox DocuShare is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input appended to the URL after:

  /dsweb/ResultBackgroundJobMultiple/1

  is not properly sanitised before being used in SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML or script code and manipulate SQL queries in the backend database allowing for the
  manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Xerox DocuShare versions 6.5.3 Patch 6, 6.6.1 Update 1, 6.6.1
  Update 2. Prior versions may also be affected.");

  script_tag(name:"solution", value:"Update to 6.53 Patch 6 Hotfix 2, 6.6.1 Update 1 Hotfix 24,
  6.6.1 Update 2 Hotfix 3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/dsweb/ResultBackgroundJobMultiple/'SQL-Inj-Test";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:">SQL error.<", extra_check:make_list( "Error Code: 1501", "SQL-Inj-Test" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
