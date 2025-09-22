# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141985");
  script_version("2021-09-06T11:58:24+0000");
  script_tag(name:"last_modification", value:"2021-09-06 11:58:24 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-02-11 13:18:48 +0700 (Mon, 11 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-13 14:16:00 +0000 (Wed, 13 Feb 2019)");

  script_cve_id("CVE-2018-20767", "CVE-2018-20768", "CVE-2018-20769", "CVE-2018-20770", "CVE-2018-20771");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox WorkCentre Printers Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Xerox WorkCentre Printers are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Xerox WorkCentre Printers are prone to multiple vulnerabilities:

  - Authenticated remote code execution (CVE-2018-20767)

  - Writable file to Execute PHP code (CVE-2018-20768)

  - Local file inclusion (CVE-2018-20769)

  - Blind SQL injection (CVE-2018-20770)

  - Unauthenticated remote code execution (CVE-2018-20771)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"WorkCentre 3655, 3655i, 58XX, 58XXi, 59XX, 59XXi, 6655, 6655i, 72XX, 72XXi,
  78XX, 78XXi, 7970, 7970i, EC7836, and EC7856 devices.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2018/07/cert_Security_Mini_Bulletin_XRX18Y_for_ConnectKey_EC78xx_v1.0.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:workcentre_3655_firmware",
                     "cpe:/o:xerox:workcentre_3655i_firmware",
                     "cpe:/o:xerox:workcentre_5845_firmware",
                     "cpe:/o:xerox:workcentre_5855_firmware",
                     "cpe:/o:xerox:workcentre_5865_firmware",
                     "cpe:/o:xerox:workcentre_5865i_firmware",
                     "cpe:/o:xerox:workcentre_5875_firmware",
                     "cpe:/o:xerox:workcentre_5875i_firmware",
                     "cpe:/o:xerox:workcentre_5890_firmware",
                     "cpe:/o:xerox:workcentre_5890i_firmware",
                     "cpe:/o:xerox:workcentre_5945_firmware",
                     "cpe:/o:xerox:workcentre_5945i_firmware",
                     "cpe:/o:xerox:workcentre_5955_firmware",
                     "cpe:/o:xerox:workcentre_5955i_firmware",
                     "cpe:/o:xerox:workcentre_6655_firmware",
                     "cpe:/o:xerox:workcentre_6655i_firmware",
                     "cpe:/o:xerox:workcentre_7220_firmware",
                     "cpe:/o:xerox:workcentre_7220i_firmware",
                     "cpe:/o:xerox:workcentre_7225_firmware",
                     "cpe:/o:xerox:workcentre_7225i_firmware",
                     "cpe:/o:xerox:workcentre_7830_firmware",
                     "cpe:/o:xerox:workcentre_7830i_firmware",
                     "cpe:/o:xerox:workcentre_7835_firmware",
                     "cpe:/o:xerox:workcentre_7835i_firmware",
                     "cpe:/o:xerox:workcentre_7845_firmware",
                     "cpe:/o:xerox:workcentre_7845i_firmware",
                     "cpe:/o:xerox:workcentre_7855_firmware",
                     "cpe:/o:xerox:workcentre_7855i_firmware",
                     "cpe:/o:xerox:workcentre_7970_firmware",
                     "cpe:/o:xerox:workcentre_7970i_firmware",
                     "cpe:/o:xerox:workcentre_ec7836_firmware",
                     "cpe:/o:xerox:workcentre_ex7856_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:xerox:workcentre_3655_firmware" || cpe == "cpe:/o:xerox:workcentre_3655i_firmware") {
  if (version_is_less(version: version, test_version: "073.060.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.060.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_5845_firmware" || cpe == "cpe:/o:xerox:workcentre_5855_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5865_firmware" || cpe == "cpe:/o:xerox:workcentre_5875_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5890_firmware" || cpe == "cpe:/o:xerox:workcentre_5865i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5875i_firmware" || cpe == "cpe:/o:xerox:workcentre_5890i_firmware") {
  if (version_is_less(version: version, test_version: "073.190.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.190.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_5945_firmware" || cpe == "cpe:/o:xerox:workcentre_5945i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5955_firmware" || cpe == "cpe:/o:xerox:workcentre_5945i_firmware") {
  if (version_is_less(version: version, test_version: "073.091.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.091.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_6655_firmware" || cpe == "cpe:/o:xerox:workcentre_6655i_firmware") {
  if (version_is_less(version: version, test_version: "073.110.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.110.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7220_firmware" || cpe == "cpe:/o:xerox:workcentre_7220i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7225_firmware" || cpe == "cpe:/o:xerox:workcentre_7225i_firmware") {
  if (version_is_less(version: version, test_version: "073.030.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.030.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7830_firmware" || cpe == "cpe:/o:xerox:workcentre_7830i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7835_firmware" || cpe == "cpe:/o:xerox:workcentre_7835i_firmware") {
  if (version_is_less(version: version, test_version: "073.010.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.010.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7845_firmware" || cpe == "cpe:/o:xerox:workcentre_7845i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7855_firmware" || cpe == "cpe:/o:xerox:workcentre_7855i_firmware") {
  if (version_is_less(version: version, test_version: "073.040.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.040.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7970_firmware" || cpe == "cpe:/o:xerox:workcentre_7970i_firmware") {
  if (version_is_less(version: version, test_version: "073.200.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.200.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7836_firmware") {
  if (version_is_less(version: version, test_version: "073.050.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.050.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7856_firmware") {
  if (version_is_less(version: version, test_version: "073.020.048.15000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.020.048.15000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
