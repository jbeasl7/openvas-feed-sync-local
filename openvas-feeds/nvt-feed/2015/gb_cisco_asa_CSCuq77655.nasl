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
  script_oid("1.3.6.1.4.1.25623.1.0.105999");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-05-29 14:26:28 +0700 (Fri, 29 May 2015)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-0676");

  script_name("Cisco ASA DNS Memory Exhaustion Vulnerability (cisco-sa-20150408-asa)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"Cisco ASA is prone to a DNS memory exhaustion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of DNS packets.
  An attacker could exploit this vulnerability by sending a request to an affected Cisco ASA
  appliance, which can cause it to generate a DNS request packet. The attacker would need to be
  able to intercept this request and reply with a crafted DNS reply packet.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this
  vulnerability by sending a request to a targeted device, causing the device to generate a DNS
  request packet. If the attacker can intercept the request and reply with a crafted DNS packet,
  the attacker could cause the device to exhaust available memory resources to cause system
  instability that results in a DoS condition.");

  script_tag(name:"affected", value:"Cisco ASA version 7.2, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 9.0, 9.1,
  9.2, 9.3.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150408-asa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.2", test_version_up: "7.2.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2(5.16)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.5.57")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(5.57)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.2.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3(2.44)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.7.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.28)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.1.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5(1.24)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.6", test_version_up: "8.6.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6(1.17)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.7", test_version_up: "8.7.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7(1.16)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.33)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(6.1)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2(3.4)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3(3)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
