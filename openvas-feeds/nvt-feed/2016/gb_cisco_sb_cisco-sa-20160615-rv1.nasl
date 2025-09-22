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

CPE_PREFIX = "cpe:/o:cisco:rv";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105769");
  script_version("2022-02-04T05:57:42+0000");
  script_tag(name:"last_modification", value:"2022-02-04 05:57:42 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-06-17 13:54:53 +0200 (Fri, 17 Jun 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-30 03:04:00 +0000 (Wed, 30 Nov 2016)");

  script_cve_id("CVE-2016-1396");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco RV110W, RV130W, and RV215W Routers XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_small_business_devices_consolidation.nasl");
  script_mandatory_keys("cisco/small_business/detected");

  script_tag(name:"summary", value:"A vulnerability in the web-based management interface of Cisco
  RV110W Wireless-N VPN Firewalls, Cisco RV130W Wireless-N Multifunction VPN Routers, and Cisco
  RV215W Wireless-N VPN Routers could allow an unauthenticated, remote attacker to conduct a
  cross-site scripting (XSS) attack against a user of the web-based management interface for a
  targeted device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation of
  certain parameters that are sent to an affected device via the HTTP GET or HTTP POST method. An
  unauthenticated, remote attacker could exploit this vulnerability by persuading a user to follow
  a link that is designed to submit malicious input to an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute
  arbitrary script in the context of the web-based management interface for the device or allow the
  attacker to access sensitive browser-based information.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160615-rv1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:cisco:rv(1[13]0|215)w")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:cisco:rv110w_firmware") {
  affected = make_list(
    "1.1.0.9",
    "1.2.0.10",
    "1.2.0.9",
    "1.2.1.4"
  );
}

if (cpe == "cpe:/o:cisco:rv130w_firmware") {
  affected = make_list(
    "1.0.0.21",
    "1.0.1.3",
    "1.0.2.7"
  );
}

if (cpe == "cpe:/o:cisco:rv215w_firmware") {
  affected = make_list(
    "1.1.0.5",
    "1.1.0.6",
    "1.2.0.14",
    "1.2.0.15",
    "1.3.0.7"
  );
}

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
