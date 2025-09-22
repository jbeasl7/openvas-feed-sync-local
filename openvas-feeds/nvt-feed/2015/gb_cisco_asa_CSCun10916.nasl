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
  script_oid("1.3.6.1.4.1.25623.1.0.105987");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-03-13 13:47:16 +0700 (Fri, 13 Mar 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3394");

  script_name("Cisco ASA Smart Call Home Digital Certificate Validation Vulnerability (cisco-sa-20141008-asa)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in the Smart Call Home (SCH) feature of Cisco
  ASA Software could allow an unauthenticated, remote attacker to bypass digital certificate
  validation if any feature that uses digital certificates is configured on the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because when SCH is configured, a
  trustpoint, including a VeriSign certificate, is automatically installed. An attacker could
  exploit this vulnerability by presenting a valid certificate signed by VeriSign when
  authenticating to the affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to gain remote
  access to the inside network, which could be used to conduct further attacks.");

  script_tag(name:"affected", value:"Cisco ASA version 8.2, 8.4, 8.6, 8.7, 9.0 and 9.1.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141008-asa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.5.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(5.50)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.7.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.15)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.6", test_version_up: "8.6.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6(1.14)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.7", test_version_up: "8.7.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7(1.13)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.8)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(5.1)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
