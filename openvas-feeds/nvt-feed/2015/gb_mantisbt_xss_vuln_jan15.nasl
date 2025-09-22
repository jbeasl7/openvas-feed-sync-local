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
  script_oid("1.3.6.1.4.1.25623.1.0.805236");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-8986");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-01-08 18:58:08 +0530 (Thu, 08 Jan 2015)");
  script_name("MantisBT 1.2.13 - 1.2.17 'adm_config_report.php' XSS Vulnerability");

  script_tag(name:"summary", value:"MantisBT is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the
  adm_config_report.php script does not validate input when handling
  the config file option before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the
  server.");

  script_tag(name:"affected", value:"MantisBT version 1.2.13 through 1.2.17.");

  script_tag(name:"solution", value:"Update to version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/11/15/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71197");
  script_xref(name:"URL", value:"https://github.com/mantisbt/mantisbt/commit/cabacdc291c251bfde0dc2a2c945c02cef41bf40");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

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

if (version_in_range(version: version, test_version: "1.2.13", test_version2: "1.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
