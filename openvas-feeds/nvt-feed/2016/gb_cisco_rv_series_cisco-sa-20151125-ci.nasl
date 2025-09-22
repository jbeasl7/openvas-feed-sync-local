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

CPE_PREFIX = "cpe:/o:cisco:rv32";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106248");
  script_version("2022-02-04T05:57:42+0000");
  script_tag(name:"last_modification", value:"2022-02-04 05:57:42 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-09-15 12:51:33 +0700 (Thu, 15 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 16:46:00 +0000 (Fri, 03 Nov 2017)");

  script_cve_id("CVE-2015-6358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Small Business RV Series Confidential Information Decryption Man-in-the-Middle Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_small_business_devices_consolidation.nasl");
  script_mandatory_keys("cisco/small_business/detected");

  script_tag(name:"summary", value:"A vulnerability in the cryptographic implementation of the
  RV320 Dual Gigabit WAN VPN Router and the RV325 Dual Gigabit WAN VPN Router could allow an
  unauthenticated, remote attacker to make use of hard-coded certificate and keys embedded within
  the firmware of the affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the lack of unique key and
  certificate generation within affected appliances.

  This is an attack on the client attempting to access the device and does not compromise the
  device itself. To exploit the issue, an attacker needs not only the public and private key pair
  but also a privileged position in the network that would allow him or her to  monitor the traffic
  between client and server, intercept the traffic, and modify or inject its own traffic.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by using the static
  information to conduct man-in-the-middle attacks to decrypt confidential information on user
  connections.");

  script_tag(name:"affected", value:"RV320 Dual Gigabit WAN VPN Router and RV325 Dual Gigabit WAN
  VPN Router.");

  script_tag(name:"solution", value:"Update to Firmware version 1.3.1.12 or later.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151125-ci");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:cisco:rv32[25]_firmware")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1.12");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
