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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106183");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-08-18 10:57:32 +0700 (Thu, 18 Aug 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 13:08:59 +0000 (Tue, 02 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-6366");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Adaptive Security Appliance SNMP Remote Code Execution Vulnerability (cisco-sa-20160817-asa-snmp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in the Simple Network Management Protocol
  (SNMP) code of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated,
  remote attacker to cause a reload of the affected system or to remotely execute code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a buffer overflow in the affected
  code area. An attacker could exploit this vulnerability by sending crafted SNMP packets to the
  affected system. An exploit could allow the attacker to execute arbitrary code and obtain full
  control of the system or to cause a reload of the affected system. The attacker must know the
  SNMP community string to exploit this vulnerability.

  Note: Only traffic directed to the affected system can be used to exploit this vulnerability.
  This vulnerability affects systems configured in routed and transparent firewall mode only and in
  single or multiple context mode. This vulnerability can be triggered by IPv4 traffic only. The
  attacker requires knowledge of the configured SNMP community string in SNMP version 1 and SNMP
  version 2c or a valid username and password for SNMP version 3.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "9.0.4.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.4(40)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.7(9)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.4(14)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.3(10)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.3(8)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.5", test_version_up: "9.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5(3)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.6", test_version_up: "9.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6(2)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
