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
  script_oid("1.3.6.1.4.1.25623.1.0.106011");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-06-23 09:56:22 +0700 (Tue, 23 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-4550");

  script_name("Cisco ASA AES-GCM Vulnerability (Cisco-SA-20150616-CVE-2015-4550)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"Cisco ASA is prone to an encrypted IPSec or IKEv2 modification
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to an error on the firmware of the
  Cavium Networks cryptographic module. Due to this vulnerability, the integrity check value (ICV)
  is not verified. An attacker could exploit this vulnerability by intercepting encrypted packets
  in transit and modifying their contents. Such packets would be decrypted by the ASA and then
  forwarded to their destination, without the modification being detected.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could modify the contents of
  an encrypted IPSec or IKEv2 packet. A successful exploit could be leveraged to conduct further
  attacks.");

  script_tag(name:"affected", value:"Cisco ASA version 9.3 and 9.4.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150616-CVE-2015-4550");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3(3.2)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4(1.2)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
