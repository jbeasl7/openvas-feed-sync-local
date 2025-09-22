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

CPE = "cpe:/a:sitecore:cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805497");
  script_version("2021-11-11T07:42:51+0000");
  script_tag(name:"last_modification", value:"2021-11-11 07:42:51 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"creation_date", value:"2015-03-20 10:14:06 +0530 (Fri, 20 Mar 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-100004");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sitecore CMS <= 7.0 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sitecore_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sitecore/cms/http/detected");

  script_tag(name:"summary", value:"Sitecore CMS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The default.aspx script does not validate input to the
  'xmlcontrol' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Sitecore CMS before 7.0 Update-4 (rev. 140120).");

  script_tag(name:"solution", value:"Update to version 7.0 Update-4 (rev. 140120) or later.");

  script_xref(name:"URL", value:"http://www.idappcom.com/db/?9066");
  script_xref(name:"URL", value:"http://sitecorekh.blogspot.dk/2014/01/sitecore-releases-70-update-4-rev-140120.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/login?xmlcontrol=body%20onload=alert%28document.cookie%29";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"alert\(document\.cookie\)" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );