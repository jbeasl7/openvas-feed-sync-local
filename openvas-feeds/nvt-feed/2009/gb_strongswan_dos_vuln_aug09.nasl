# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800673");
  script_version("2021-10-21T06:59:14+0000");
  script_tag(name:"last_modification", value:"2021-10-21 06:59:14 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2009-2661");

  script_name("strongSwan DoS Vulnerability (Aug 2009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'asn1_length()' function in the
  'libstrongswan/asn1/asn1.c' script. It does not properly handle X.509 certificates with crafted
  Relative Distinguished Names (RDNs).");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash pluto IKE daemon,
  corrupt memory and can cause a denial of service.");

  script_tag(name:"affected", value:"strongSwan version 2.8.x prior to 2.8.11, 4.2.x prior to
  4.2.17 and 4.3.x prior to 4.3.3.");

  script_tag(name:"solution", value:"Update to version 2.8.11, 4.2.17, 4.3.3 or later.");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/383254.php");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/07/27/1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.8.0", test_version2: "2.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.11", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.17", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);