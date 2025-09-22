# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812033");
  script_version("2022-09-09T10:12:35+0000");
  script_cve_id("CVE-2016-8743");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-09-09 10:12:35 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:39:00 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2017-10-16 18:12:40 +0530 (Mon, 16 Oct 2017)");
  ##qod is remote_banner_unreliable as Apache is vulnerable only
  ##when httpd is participating in any chain of proxies or interacting with back-end
  ##application servers, either through mod_proxy or using conventional CGI mechanisms.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server 'Whitespace Defects' Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist because the application accepted a
  broad pattern of unusual whitespace patterns from the user-agent, including
  bare CR, FF, VTAB in parsing the request line and request header lines, as
  well as HTAB in parsing the request line. Any bare CR present in request
  lines was treated as whitespace and remained in the request field member
  'the_request', while a bare CR in the request header field name would be
  honored as whitespace, and a bare CR in the request header field value was
  retained the input headers array. Implied additional whitespace was accepted
  in the request line and prior to the ':' delimiter of any request header lines.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct request smuggling, response splitting and cache pollution
  attacks.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x before 2.2.32 and
  2.3.x through 2.4.24 prior to 2.4.25.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.2.32 or 2.4.25
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95077");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^2\.[34]") {
  if(version_is_less(version:vers, test_version:"2.4.25")) {
    fix = "2.4.25";
  }
}

else if(vers =~ "^2\.2") {
  if(version_is_less(version:vers, test_version:"2.2.32")) {
    fix = "2.2.32";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
