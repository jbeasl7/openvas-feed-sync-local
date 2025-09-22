# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810675");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-3831");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-22 15:33:08 +0530 (Wed, 22 Mar 2017)");

  script_name("Cisco Mobility Express 1800 Series Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"Cisco Mobility Express 1800 Series Access Point is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to an improper
  implementation of authentication for accessing certain web pages using the GUI
  interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass authentication. The attacker could be granted full
  administrator privileges.");

  script_tag(name:"affected", value:"Cisco Aironet Access Point Software versions
  8.1(112.3), 8.1(112.4), 8.1(15.14) and 8.1(131.0)");

  script_tag(name:"solution", value:"Upgrade to Cisco Aironet Access Point
  Software version 8.2.130.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy68219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96909");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-ap1800");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wlc_consolidation.nasl");
  script_mandatory_keys("cisco/wlc/detected", "cisco/wlc/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco/wlc/model");
if (!model || model !~ "^AIR-AP1800")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list("8.1.112.3",
                     "8.1.112.4",
                     "8.1.15.14",
                     "8.1.131.0");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.2.130.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
