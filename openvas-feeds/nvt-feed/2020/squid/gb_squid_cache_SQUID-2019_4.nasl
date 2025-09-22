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

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143765");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2020-04-24 07:57:13 +0000 (Fri, 24 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-09 16:55:00 +0000 (Tue, 09 Feb 2021)");

  script_cve_id("CVE-2019-12520", "CVE-2019-12524");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid 3.5.18 - 3.5.28 / 4.0.10 - 4.7 Multiple Vulnerabilities (SQUID-2019:4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Due to incorrect URL handling Squid is vulnerable to access
  control bypass, cache poisoning and cross-site scripting attacks when processing HTTP Request
  messages.");

  script_tag(name:"impact", value:"A remote client can:

  - deliver crafted URLs to bypass cache manager security controls and retrieve confidential details
  about the proxy and traffic it is handling.

  - deliver crafted URLs which cause arbitrary content from one origin server to be stored in cache
  as URLs within another origin. This opens a window of opportunity for clients to be tricked into
  fetching and XSS execution of that content via side channels.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid proxy 3.5.18 through 3.5.28 and 4.0.10 through 4.7.

  Note: All Squid-4.x up to and including 4.7 without HTTPS support are NOT vulnerable.");

  script_tag(name:"solution", value:"Update to version 4.8 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12520.txt");
  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12524.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_4.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version:version, test_version:"3.5.18", test_version2:"3.5.28" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.8", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

else if( version_in_range( version:version, test_version:"4.0.10", test_version2:"4.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.8", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );