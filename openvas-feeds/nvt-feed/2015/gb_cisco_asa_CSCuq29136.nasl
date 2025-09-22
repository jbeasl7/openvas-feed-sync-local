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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105985");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-03-13 13:21:11 +0700 (Fri, 13 Mar 2015)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3392");

  script_name("Cisco ASA Clientless VPN Information Disclosure and DoS Vulnerability (cisco-sa-20141008-asa)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in the Clientless SSL VPN portal feature could
  allow an unauthenticated, remote attacker to access random memory locations. Due to this
  vulnerability, the attacker may be able to access the information stored in memory and in some
  cases may be able to corrupt this portion of memory, which could lead to a reload of the affected
  system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of
  user-supplied input. An authenticated, remote attacker could exploit this vulnerability by
  setting random values on parameters passed during access to the Clientless SSL VPN portal.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to access
  sensitive information in memory. In some cases, the attacker could corrupt a portion of memory
  that could cause the targeted device to reload abnormally. Repeated exploitation could lead to a
  sustained DoS condition for legitimate users.");

  script_tag(name:"affected", value:"Cisco ASA version 8.2, 8.3, 8.4, 8.6, 9.0, 9.1, 9.2 and 9.3.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141008-asa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.5.51")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(5.51)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.2.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3(2.42)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.7.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.23)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.6", test_version_up: "8.6.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6(1.15)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.24)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(5.12)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2(2.8)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3(1.1)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
