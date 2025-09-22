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

CPE = "cpe:/a:bmc:track-it%21";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105932");
  script_version("2022-02-23T03:44:27+0000");
  script_tag(name:"last_modification", value:"2022-02-23 03:44:27 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2014-11-20 11:15:27 +0700 (Thu, 20 Nov 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-4872", "CVE-2014-4873", "CVE-2014-4874");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BMC Track-It! <= 11.3.0.355 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bmc_trackit_http_detect.nasl");
  script_mandatory_keys("bmc/trackit/detected");

  script_tag(name:"summary", value:"BMC Track-It! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-4872: BMC Track-It! exposes several dangerous remote .NET services on port 9010
  without authentication. .NET remoting allows a user to invoke methods remotely and retrieve their
  result.

  - CVE-2014-4873: An authenticated user can engage in blind SQL Injection by entering comparison
  operators in the POST string for the /TrackItWeb/Grid/GetData page.

  - CVE-2014-4874: A remote authenticated user can download arbitrary files on the
  /TrackItWeb/Attachment page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform
  SQL injections, arbitrary file upload/download and code execution.");

  script_tag(name:"affected", value:"BMC Track-It! version 11.3.0.355 and below.");

  script_tag(name:"solution", value:"Hotfixes are available for CVE-2014-4873 and CVE-2014-4874.

  For CVE-2014-4872 there is currently no hotfix available. As a workaround block all traffic from
  untrusted networks to TCP/UDP ports 9010 to 9020.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70265");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "11.3.0.355")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply hotfix", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
