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
  script_oid("1.3.6.1.4.1.25623.1.0.106012");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-06-23 09:56:22 +0700 (Tue, 23 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-0760");

  script_name("Cisco ASA XAUTH Bypass Vulnerability (Cisco-SA-20150602-CVE-2015-0760)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in IKE version 1 code of Cisco ASA Software
  could allow an authenticated, remote attacker to bypass Extended Authentication (XAUTH) and
  successfully log in via IPsec remote VPN.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper implementation of the
  logic of the XAUTH code. An authenticated, remote attacker could exploit this vulnerability to
  bypass authentication and gain network access to an environment an affected device is protecting.");

  script_tag(name:"impact", value:"A successful exploit could be used to conduct further attacks.");

  script_tag(name:"affected", value:"Cisco ASA version 7.x, 8.0, 8.1 and 8.2.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150602-CVE-2015-0760");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.2.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2(5.16)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.5.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0(5.17)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.2.45")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1(2.45)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(2.13)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
