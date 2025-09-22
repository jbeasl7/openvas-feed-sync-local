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
  script_oid("1.3.6.1.4.1.25623.1.0.106054");
  script_version("2022-02-14T09:43:40+0000");
  script_tag(name:"last_modification", value:"2022-02-14 09:43:40 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-11-25 11:40:51 +0700 (Wed, 25 Nov 2015)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-6325");

  script_name("Cisco ASA DNS DoS Vulnerability (cisco-sa-20151021-asa-dns1)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version", "cisco_asa/model");

  script_tag(name:"summary", value:"A vulnerability in the DNS code of Cisco ASA may lead to a
  denial of service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the DNS code could allow an unauthenticated,
  remote attacker to cause an affected system to reload. The vulnerability is due to improper
  processing of DNS packets. An attacker could exploit this vulnerability by sending a request to
  an affected Cisco ASA appliance to cause it to generate a DNS request packet. The attacker would
  need to spoof the reply packet with a crafted DNS response. Only traffic directed to the affected
  device can be used to exploit this vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could cause the system to
  reload.");

  script_tag(name:"affected", value:"Version 7.2, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 9.0, 9.1, 9.2, 9.3
  and 9.4 on Cisco Adaptive Security Virtual Appliance (ASAv), Cisco ASA 1000V Cloud Firewall,
  Cisco ASA 5500 Series Adaptive Security Appliances, Cisco ASA 5500-X Series Next-Generation
  Firewalls, Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600
  Series Routers.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dns1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_asa/model");
if (!model || (toupper(model) !~ "^ASAv" && toupper(model) !~ "^ASA55[0-9][0-9]"))
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.2", test_version_up: "8.2.5.58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2(5.58)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.4.7.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4(7.29)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^8\.[56]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.37)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.7", test_version_up: "8.7.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7(1.17)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.4.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0(4.37)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1(6.4)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2(4)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3(1)");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.4", test_version_up: "9.4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4(1.1)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
