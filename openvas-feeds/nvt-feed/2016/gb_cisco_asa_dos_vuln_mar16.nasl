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
  script_oid("1.3.6.1.4.1.25623.1.0.806690");
  script_version("2022-02-14T09:43:40+0000");
  script_tag(name:"last_modification", value:"2022-02-14 09:43:40 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-03-22 12:49:04 +0530 (Tue, 22 Mar 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-1312");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco ASA 5500 Devices DoS Vulnerability (cisco-sa-20160309-csc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version", "cisco_asa/model");

  script_tag(name:"summary", value:"Cisco ASA 5500 devices are prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the HTTPS inspection engine of
  the Cisco ASA Content Security and Control Security Services Module (CSC-SSM) which improperly
  handles HTTPS packets transiting through the affected system.");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to cause exhaustion
  of available memory, system instability, and a reload of the affected system.");

  script_tag(name:"affected", value:"Cisco ASA 5500-X Series Firewalls with software version 6.6.x
  prior to 6.6.1164.0.

  Note: Cisco ASA 5500-X Series Firewalls with version 6.6.1157.0 are not vulnerable.");

  script_tag(name:"solution", value:"Update to version 6.6.1164.0 or later.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160309-csc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_asa/model");
if (!model || model !~ "^ASA55[0-9][0-9]")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.6", test_version_up: "6.6.1157.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.1157.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
