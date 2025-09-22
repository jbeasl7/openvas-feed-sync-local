# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151894");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-11 05:00:27 +0000 (Mon, 11 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2024-0407");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Information Disclosure Vulnerability (HPSBPI03918)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to an information disclosure
  vulnerability when connections made by the device back to services enabled by some solutions may
  have been trusted without the appropriate CA certificate in the device's certificate store.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_10174094-10174120-16/hpsbpi03918");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_x65465dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_x65455dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_x654dn_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046165")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046165 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_x677dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_x67755dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_x67765dn_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046167")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046167 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_5700_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046154")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046154 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_flow_mfp_5800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_5800_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046168")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046168 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_6700_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_6701_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046165")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046165 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_6800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_6800_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046167")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046167 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m455_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046160")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046160 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m480_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046159")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046159 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_M55[45]_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046130")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046130 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m577_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m578_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m578_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046140")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046140 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m652_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_m653_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046145")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046145 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_m68[12]_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_m68[12]_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040437")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040437 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m751_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046129")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046129 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m776_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m776_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046127")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046127 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m856_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046112")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046112 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e45028_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046160")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046160 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e55040dw_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046130")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046130 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_e65[01][56]0_firmware") {
  if (version_is_less(version: version, test_version: "2507252.0461450")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046145 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e75245_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046129")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046129 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e85055_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046112")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046112 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e47528_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046159")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046159 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e57540_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e57540_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046140")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046140 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_e675[56]0_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e676[56]0_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046117")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046117 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7742[2-8]_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046111")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046111 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_e778(22|25|30)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046144")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046144 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7822[3-8]_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046111")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046111 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e783(23|30)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046144")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046144 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e785dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78523_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78528_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046153")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046153 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e786_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e786_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_e786(25|30|35)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046166")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046166 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_e876(40|50|60)_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e876[4-6]0du_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046136")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046136 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e877_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_(flow_)?mfp_e877(40|50|60|70)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046156")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046156 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_x55745_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046154")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046154 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_x57945_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_x57945_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_x58045_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046168")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046168 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m406_firmware" ||
    cpe == "cpe:/o:hp:laserjet_m407_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046161")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046161 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m430_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_m431_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046158")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046158 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m507_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046139")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046139 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_(flow_)mfp_m527z?_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046115")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046115 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m528_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046124")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046124 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m606_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046149")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046149 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_m60(7|8|9|10|11|12)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046110")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046110 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_m63[1-6]_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046123")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046123 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e40040_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046161")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046161 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e42540_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046158")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046158 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e50045_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046147")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046147 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e50145_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046139")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046139 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52545_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e52545c_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046115")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046115 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52645_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046124")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046124 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_e60[01][567]5_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046110")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046110 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_e62[56][56]5_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_flow_mfp_e625[567]5_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62675_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046123")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046123 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_e724(25|30)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046142")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046142 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_e725(25|30|35)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046132")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046132 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e730_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_mfp_e730(25|30)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046155")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046155 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_e731_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_e731(30|35|40)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046164")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046164 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_(flow_)?mfp_e825(40|50|60)_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_mfp_e825(40|50|60du)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046133")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046133 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =- "cpe:/o:hp:laserjet_mfp e826dn_firmware" ||
    cpe =- "cpe:/o:hp:laserjet_flow_mfp e826z_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_(flow_)?e826(50|60|70)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046162")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046162 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_556_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046125")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046125 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_586_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_586z_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046109")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046109 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_755_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_765_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046143")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046143 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_774_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_779_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046137")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046137 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_flow_mfp_785_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_780_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_780f_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046113")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040454 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_e55650_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046125")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046125 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e58650dn_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_e58650z_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046109")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046109 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_e75160_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_p75250_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046143")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046143 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_p77440_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046137")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046137 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e77650_firmware" ||
    cpe =~ "^cpe:/o:hp:pagewide_color_flow_mfp_e776(50|60z)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046113")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046113 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:pagewide_color_mfp_p779(40|50|60)_firmware") {
  if (version_is_less(version: version, test_version: "2507252.046137")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2507252_046137 (5.7.1.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
