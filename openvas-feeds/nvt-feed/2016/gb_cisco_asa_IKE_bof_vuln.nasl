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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806682");
  script_version("2022-02-10T15:02:13+0000");
  script_tag(name:"last_modification", value:"2022-02-10 15:02:13 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-02-11 14:20:25 +0530 (Thu, 11 Feb 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-06 16:15:00 +0000 (Fri, 06 Jan 2017)");

  script_cve_id("CVE-2016-1287");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco ASA Software IKEv1 and IKEv2 Buffer Overflow Vulnerability (cisco-sa-20160210-asa-ike)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"Cisco ASA Software is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to buffer overflow error in the
  Internet Key Exchange (IKE) version 1 (v1) and IKE version 2 (v2) code.");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to
  execute arbitrary code and obtain full control of the system or to cause a reload
  of the affected system.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^(7\.2|8\.[0136]\.)") {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(6.11)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.5.59")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(5.59)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.7.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.30)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.7", test_version_up: "8.7.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7(1.18)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.38)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.6.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(6.11)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2(4.5)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3(3.7)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4(2.4)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.5", test_version_up: "9.5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5(2.2)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
