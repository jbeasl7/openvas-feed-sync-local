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
  script_oid("1.3.6.1.4.1.25623.1.0.147246");
  script_version("2022-02-16T04:46:07+0000");
  script_tag(name:"last_modification", value:"2022-02-16 04:46:07 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2021-12-03 03:12:57 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 21:07:00 +0000 (Thu, 04 Nov 2021)");

  script_cve_id("CVE-2021-39237");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Information Disclosure Vulnerability (HPSBPI03748)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printers are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet, HP LaserJet Managed, HP PageWide, and HP
  PageWide Managed printers may be vulnerable to potential information disclosure.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_5000124-5000148-16");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:hp:color_laserjet_cm4540_mfp_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m578_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m578_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m880_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m880_firmware",
                     "cpe:/o:hp:color_laserjet_m455_firmware",
                     "cpe:/o:hp:color_laserjet_m552_firmware",
                     "cpe:/o:hp:color_laserjet_m553_firmware",
                     "cpe:/o:hp:color_laserjet_m555_firmware",
                     "cpe:/o:hp:color_laserjet_m651_firmware",
                     "cpe:/o:hp:color_laserjet_m652_firmware",
                     "cpe:/o:hp:color_laserjet_m653_firmware",
                     "cpe:/o:hp:color_laserjet_m750_firmware",
                     "cpe:/o:hp:color_laserjet_m751_firmware",
                     "cpe:/o:hp:color_laserjet_e75245_firmware",
                     "cpe:/o:hp:color_laserjet_m855_firmware",
                     "cpe:/o:hp:color_laserjet_m856_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m480_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m577_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m680_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m680_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m681_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m681_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m682_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m682_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m776_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m776_firmware",
                     "cpe:/o:hp:color_laserjet_cp5525_firmware",
                     "cpe:/o:hp:color_laserjet_e45028_firmware",
                     "cpe:/o:hp:color_laserjet_e55040_firmware",
                     "cpe:/o:hp:color_laserjet_e65050_firmware",
                     "cpe:/o:hp:color_laserjet_e65060_firmware",
                     "cpe:/o:hp:color_laserjet_e85055_firmware",
                     "cpe:/o:hp:color_laserjet_e47528_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e57540_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e57540_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e67550_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e67550_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e67560_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e67560_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e67650_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e67660_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77422_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77423_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77424_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77425_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77426_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77427_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77428_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77429_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77822_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e77822_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77825_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e77825_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77830_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e77830_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77223_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77224_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77225_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77226_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77227_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e77223_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e78323_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e78330_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e87640_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e87640_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e87650_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e87650_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_e87660_firmware",
                     "cpe:/o:hp:color_laserjet_flow_e87660_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m577_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware",
                     "cpe:/o:hp:laserjet_500_color_mfp_m575_firmware",
                     "cpe:/o:hp:laserjet_500_color_flow_mfp_m575_firmware",
                     "cpe:/o:hp:laserjet_500_color_m551_firmware",
                     "cpe:/o:hp:laserjet_500_color_mfp_m525_firmware",
                     "cpe:/o:hp:laserjet_500_color_flow_mfp_m525_firmware",
                     "cpe:/o:hp:laserjet_600_m601_firmware",
                     "cpe:/o:hp:laserjet_600_m602_firmware",
                     "cpe:/o:hp:laserjet_600_m603_firmware",
                     "cpe:/o:hp:laserjet_700_color_mfp_m775_firmware",
                     "cpe:/o:hp:laserjet_700_m712_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m830_firmware",
                     "cpe:/o:hp:laserjet_m406_firmware",
                     "cpe:/o:hp:laserjet_m407_firmware",
                     "cpe:/o:hp:laserjet_m4555_mfp_firmware",
                     "cpe:/o:hp:laserjet_m506_firmware",
                     "cpe:/o:hp:laserjet_m507_firmware",
                     "cpe:/o:hp:laserjet_m604_firmware",
                     "cpe:/o:hp:laserjet_m605_firmware",
                     "cpe:/o:hp:laserjet_m606_firmware",
                     "cpe:/o:hp:laserjet_m607_firmware",
                     "cpe:/o:hp:laserjet_m608_firmware",
                     "cpe:/o:hp:laserjet_m609_firmware",
                     "cpe:/o:hp:laserjet_m610_firmware",
                     "cpe:/o:hp:laserjet_m611_firmware",
                     "cpe:/o:hp:laserjet_m612_firmware",
                     "cpe:/o:hp:laserjet_m806_firmware",
                     "cpe:/o:hp:laserjet_mfp_m430_firmware",
                     "cpe:/o:hp:laserjet_mfp_m431_firmware",
                     "cpe:/o:hp:laserjet_mfp_m527_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m527_firmware",
                     "cpe:/o:hp:laserjet_mfp_m528_firmware",
                     "cpe:/o:hp:laserjet_mfp_m630_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m630_firmware",
                     "cpe:/o:hp:laserjet_mfp_m631_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m631_firmware",
                     "cpe:/o:hp:laserjet_mfp_m632_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m632_firmware",
                     "cpe:/o:hp:laserjet_mfp_m633_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m633_firmware",
                     "cpe:/o:hp:laserjet_mfp_m634_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m634_firmware",
                     "cpe:/o:hp:laserjet_mfp_m635_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m635_firmware",
                     "cpe:/o:hp:laserjet_mfp_m636_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m636_firmware",
                     "cpe:/o:hp:laserjet_mfp_m725_firmware",
                     "cpe:/o:hp:laserjet_e40040_firmware",
                     "cpe:/o:hp:laserjet_e50045_firmware",
                     "cpe:/o:hp:laserjet_e50145_firmware",
                     "cpe:/o:hp:laserjet_e60055_firmware",
                     "cpe:/o:hp:laserjet_e60065_firmware",
                     "cpe:/o:hp:laserjet_e60075_firmware",
                     "cpe:/o:hp:laserjet_mfp_e42540_firmware",
                     "cpe:/o:hp:laserjet_mfp_e42545_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_e42545_firmware",
                     "cpe:/o:hp:laserjet_mfp_e52645_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62555_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62565_firmware",
                     "cpe:/o:hp:laserjet_flow_e62555_firmware",
                     "cpe:/o:hp:laserjet_flow_e62565_firmware",
                     "cpe:/o:hp:laserjet_flow_e62575_firmware",
                     "cpe:/o:hp:laserjet_mfp_e72425_firmware",
                     "cpe:/o:hp:laserjet_mfp_e72430_firmware",
                     "cpe:/o:hp:laserjet_mfp_e72525_firmware",
                     "cpe:/o:hp:laserjet_flow_e72525_firmware",
                     "cpe:/o:hp:laserjet_mfp_e72530_firmware",
                     "cpe:/o:hp:laserjet_flow_e72530_firmware",
                     "cpe:/o:hp:laserjet_mfp_e72535_firmware",
                     "cpe:/o:hp:laserjet_flow_e72535_firmware",
                     "cpe:/o:hp:laserjet_mfp_e82540_firmware",
                     "cpe:/o:hp:laserjet_flow_e82540_firmware",
                     "cpe:/o:hp:laserjet_mfp_e82550_firmware",
                     "cpe:/o:hp:laserjet_flow_e82550_firmware",
                     "cpe:/o:hp:laserjet_mfp_e82560_firmware",
                     "cpe:/o:hp:laserjet_flow_e82560_firmware",
                     "cpe:/o:hp:officejet_color_mfp_x585_firmware",
                     "cpe:/o:hp:officejet_color_x555_firmware",
                     "cpe:/o:hp:pagewide_color_755_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_774_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_779_firmware",
                     "cpe:/o:hp:pagewide_color_556_firmware",
                     "cpe:/o:hp:pagewide_color_765_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_785_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_586_firmware",
                     "cpe:/o:hp:pagewide_color_flow_mfp_586_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_780_firmware",
                     "cpe:/o:hp:pagewide_color_flow_mfp_780_firmware",
                     "cpe:/o:hp:pagewide_color_e55650_firmware",
                     "cpe:/o:hp:pagewide_color_e75160_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e58650_firmware",
                     "cpe:/o:hp:pagewide_color_flow_e58650_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77650_firmware",
                     "cpe:/o:hp:pagewide_color_flow_e77650_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77440_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77940_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77950_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77960_firmware",
                     "cpe:/o:hp:pagewide_color_p75250_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_cm4540_mfp_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_m750_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_cp5525_firmware" ||
    cpe == "cpe:/o:hp:laserjet_600_m601_firmware" ||
    cpe == "cpe:/o:hp:laserjet_600_m602_firmware" ||
    cpe == "cpe:/o:hp:laserjet_600_m603_firmware" ||
    cpe == "cpe:/o:hp:laserjet_700_m712_firmware" ||
    cpe == "cpe:/o:hp:laserjet_m4555_mfp_firmware") {
  if (version_is_less(version: version, test_version: "3.9.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.9.8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:hp:color_laserjet_m455_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_mfp_m480_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_e45028_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_e47528_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m406_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m407_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m430_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m431_firmware" ||
         cpe == "cpe:/o:hp:laserjet_e40040_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_e42540_firmware") {
  if (version_is_less(version: version, test_version: "5.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:hp:color_laserjet_m552_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_m553_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_mfp_m577_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_mfp_e57540_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_flow_e57540_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_mfp_m577_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m506_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m604_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m605_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m606_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m527_firmware" ||
         cpe == "cpe:/o:hp:laserjet_flow_mfp_m527_firmware" ||
         cpe == "cpe:/o:hp:laserjet_e50045_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m527_firmware" ||
         cpe == "cpe:/o:hp:laserjet_flow_mfp_m527_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_556_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_mfp_586_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_flow_mfp_586_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_e55650_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_mfp_e58650_firmware" ||
         cpe == "cpe:/o:hp:pagewide_color_flow_e58650_firmware") {
  if (version_is_less(version: version, test_version: "3.9.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.9.8");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.11.2.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
      security_message(port: 0, data: report);
      exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
    security_message(port: 0, data: report);
    exit(0);
    }
}

else if (cpe == "cpe:/o:hp:color_laserjet_mfp_m880_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m880_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_m651_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_m855_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_mfp_m680_firmware" ||
         cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m680_firmware" ||
         cpe == "cpe:/o:hp:laserjet_500_color_mfp_m575_firmware" ||
         cpe == "cpe:/o:hp:laserjet_500_color_flow_mfp_m575_firmware" ||
         cpe == "cpe:/o:hp:laserjet_500_mfp_m525_firmware" ||
         cpe == "cpe:/o:hp:laserjet_500_flow_mfp_m525_firmware" ||
         cpe == "cpe:/o:hp:laserjet_700_color_mfp_m775_firmware" ||
         cpe == "cpe:/o:hp:laserjet_flow_mfp_m830_firmware" ||
         cpe == "cpe:/o:hp:laserjet_m806_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m630_firmware" ||
         cpe == "cpe:/o:hp:laserjet_flow_mfp_m630_firmware" ||
         cpe == "cpe:/o:hp:laserjet_mfp_m725_firmware" ||
         cpe == "cpe:/o:hp:officejet_color_mfp_x585_firmware" ||
         cpe == "cpe:/o:hp:officejet_color_x555_firmware") {
  if (version_is_less(version: version, test_version: "3.9.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.9.8");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.11.2.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
      security_message(port: 0, data: report);
      exit(0);
  }
}

else {
  if (version_is_less(version: version, test_version: "4.11.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.3")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
      security_message(port: 0, data: report);
      exit(0);
  }
}

exit(99);
