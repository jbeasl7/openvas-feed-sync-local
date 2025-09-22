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
  script_oid("1.3.6.1.4.1.25623.1.0.806686");
  script_version("2022-02-10T15:02:13+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-10 15:02:13 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-02-18 12:33:59 +0530 (Thu, 18 Feb 2016)");

  script_cve_id("CVE-2014-8023");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco ASA Challenge-Response Tunnel Group Selection Bypass Vulnerability (Cisco-SA-20150216-CVE-2014-8023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"Cisco ASA Software is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper implementation of the tunnel
  group selection when a user authenticates to the remote access VPN via the challenge-response
  mechanism.");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to bypass the tunnel
  group restriction and authenticate to a different tunnel group than the one selected during the
  authentication phase.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150216-CVE-2014-8023");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.4.7.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.27)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^8\.6") {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.34)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.34)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.5.100")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(5.100)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.2.100")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2(2.100)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
