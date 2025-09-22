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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806641");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-9270", "CVE-2014-9279", "CVE-2014-9269");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-12-03 16:05:34 +0530 (Thu, 03 Dec 2015)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("MantisBT 1.1.0a3 - 1.2.17 Multiple Vulnerabilities - Linux");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - the function 'projax_array_serialize_for_autocomplete' within
  core/projax_api.php script doesn't validate input passed by the user.

  - the unattended upgrade script retrieved DB connection settings from POST
  parameters allows an attacker to get the script to connect to their host with
  the current DB config credentials.

  - the input passed via project cookie to helper_api.php script is not validated
  before returning it to user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via the 'profile/Platform'
  field and gain access to sensitive information.");

  script_tag(name:"affected", value:"MantisBT versions 1.1.0a3 through 1.2.17.");

  script_tag(name:"solution", value:"Update to version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71359");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71368");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/863");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=17583");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

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

##Versions 1.1.0a2 and 1.1.0a1 are not affected
if(version == "1.1.0a2" || version == "1.1.0a1")
  exit(0);

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
