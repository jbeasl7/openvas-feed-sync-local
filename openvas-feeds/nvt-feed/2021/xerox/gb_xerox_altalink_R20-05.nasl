# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145610");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2021-03-24 03:14:50 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-23 15:05:00 +0000 (Fri, 23 Apr 2021)");

  script_cve_id("CVE-2019-18628", "CVE-2019-18630", "CVE-2019-10881");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox AltaLink Printers Multiple Vulnerabilities (XRX20I/R20-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Xerox AltaLink Printers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-18628: Removes the ability for a user with administrative privileges to turn off data
  encryption on the device and therefore no longer leaving it open to potential cryptographic
  information disclosure

  - CVE-2019-18630: Portions of the drive containing executable code were not encrypted thus leaving
  it open to potential cryptographic information disclosure

  - CVE-2019-10881: Includes two accounts with weak hard-coded passwords which can be exploited and
  allow unauthorized access");

  script_tag(name:"affected", value:"Xerox AltaLink B80xx, C8030, C8035, C8045, C8055 and C8070.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2021/03/cert_Security_Mini_Bulletin_XRX20I_for_ALB80xx-C80xx.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:altalink_b8045_firmware",
                     "cpe:/o:xerox:altalink_b8055_firmware",
                     "cpe:/o:xerox:altalink_b8065_firmware",
                     "cpe:/o:xerox:altalink_b8075_firmware",
                     "cpe:/o:xerox:altalink_b8090_firmware",
                     "cpe:/o:xerox:altalink_c8030_firmware",
                     "cpe:/o:xerox:altalink_c8035_firmware",
                     "cpe:/o:xerox:altalink_c8045_firmware",
                     "cpe:/o:xerox:altalink_c8055_firmware",
                     "cpe:/o:xerox:altalink_c8070_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe =~ "^cpe:/o:xerox:altalink_b8") {
  if (version_is_less(version: version, test_version: "103.008.010.14010")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "103.008.010.14010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:altalink_c803") {
  if (version_is_less(version: version, test_version: "103.001.010.14010")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "103.001.010.14010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:altalink_c80[45]") {
  if (version_is_less(version: version, test_version: "103.002.010.14010")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "103.002.010.14010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:altalink_c807") {
  if (version_is_less(version: version, test_version: "103.003.010.14010")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "103.003.010.14010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
