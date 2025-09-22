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
  script_oid("1.3.6.1.4.1.25623.1.0.147114");
  script_version("2022-02-16T04:46:07+0000");
  script_tag(name:"last_modification", value:"2022-02-16 04:46:07 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2021-11-05 07:42:34 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 18:33:00 +0000 (Thu, 04 Nov 2021)");

  script_cve_id("CVE-2021-3662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer XSS Vulnerability (HPSBPI03744)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP Enterprise LaserJet and PageWide MFPs may be
  vulnerable to a stored XSS.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_4577473-4577502-16/hpsbpi03744");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:hp:color_laserjet_mfp_m578_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m578_firmware",
                     "cpe:/o:hp:color_laserjet_mfp_m880_firmware",
                     "cpe:/o:hp:color_laserjet_flow_mfp_m880_firmware",
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
                     "cpe:/o:hp:laserjet_500_color_mfp_m575_firmware",
                     "cpe:/o:hp:laserjet_500_color_flow_mfp_m575_firmware",
                     "cpe:/o:hp:laserjet_500_color_mfp_m525_firmware",
                     "cpe:/o:hp:laserjet_500_color_flow_mfp_m525_firmware",
                     "cpe:/o:hp:laserjet_700_color_mfp_m775_firmware",
                     "cpe:/o:hp:laserjet_flow_mfp_m830_firmware",
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
                     "cpe:/o:hp:officejet_color_mfp_x585_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_774_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_779_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_785_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_586_firmware",
                     "cpe:/o:hp:pagewide_color_flow_mfp_586_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_780_firmware",
                     "cpe:/o:hp:pagewide_color_flow_mfp_780_firmware",
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
                     "cpe:/o:hp:laserjet_mfp_e52545_firmware",
                     "cpe:/o:hp:laserjet_flow_e52545_firmware",
                     "cpe:/o:hp:laserjet_mfp_e52546_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62555_firmware",
                     "cpe:/o:hp:laserjet_flow_e62555_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62565_firmware",
                     "cpe:/o:hp:laserjet_flow_e62565_firmware",
                     "cpe:/o:hp:laserjet_flow_e62575_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62655_firmware",
                     "cpe:/o:hp:laserjet_mfp_e62665_firmware",
                     "cpe:/o:hp:laserjet_flow_e62675_firmware",
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
                     "cpe:/o:hp:pagewide_color_mfp_e58650_firmware",
                     "cpe:/o:hp:pagewide_color_flow_e58650_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77650_firmware",
                     "cpe:/o:hp:pagewide_color_flow_e77650_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77440_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77940_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77950_firmware",
                     "cpe:/o:hp:pagewide_color_mfp_e77960_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_m880" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_m680" ||
    cpe =~ "^cpe:/o:hp:laserjet_500_color_(flow_)?mfp_m575" ||
    cpe =~ "^cpe:/o:hp:laserjet_500_(flow_)?mfp_m525" ||
    cpe == "cpe:/o:hp:laserjet_700_color_mfp_m775_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_m830_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_m630" ||
    cpe == "cpe:/o:hp:laserjet_mfp_m725_firmware" ||
    cpe == "cpe:/o:hp:officejet_color_mfp_x585_firmware") {
  if (version_is_less(version: version, test_version: "4.11.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
    security_message(port: 0, data: report);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "4.11.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^5\." && version_is_less(version: version, test_version: "5.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
