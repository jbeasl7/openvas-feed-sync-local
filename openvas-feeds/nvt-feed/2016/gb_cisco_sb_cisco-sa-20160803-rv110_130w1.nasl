# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:cisco:rv";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105846");
  script_version("2022-02-04T05:57:42+0000");
  script_tag(name:"last_modification", value:"2022-02-04 05:57:42 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-08-05 15:23:41 +0200 (Fri, 05 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-15 11:29:00 +0000 (Sat, 15 Dec 2018)");

  script_cve_id("CVE-2015-6396");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco RV110W, RV130W, and RV215W Routers Command Shell Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_small_business_devices_consolidation.nasl");
  script_mandatory_keys("cisco/small_business/detected");

  script_tag(name:"summary", value:"A vulnerability in the command-line interface (CLI) command
  parser of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N Multifunction VPN
  Router, and Cisco RV215W Wireless-N VPN Router could allow an authenticated, local attacker to
  inject arbitrary shell commands that are executed by the device. The commands are executed with
  full administrator privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"This vulnerability is fixed in the following firmware versions:

  - RV110W Wireless-N VPN Firewall, Release 1.2.1.7

  - RV130W Wireless-N Multifunction VPN Router, Release 1.0.3.16

  - RV215W Wireless-N VPN Router, Release 1.3.0.8");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-rv110_130w1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:cisco:rv[12]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:cisco:rv110w_firmware") {
  if (version_in_range(version: version, test_version: "1.2.1", test_version2: "1.2.1.6"))
    fix = "1.2.1.7";
}

if (cpe == "cpe:/o:cisco:rv130w_firmware") {
  if (version_in_range(version: version, test_version: "1.0.3", test_version2: "1.0.3.15"))
    fix = "1.0.3.16";
}

if (cpe == "cpe:/o:cisco:rv215w_firmware") {
  if(version_in_range(version: version, test_version: "1.3.0", test_version2: "1.3.0.7"))
    fix = "1.3.0.8";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
