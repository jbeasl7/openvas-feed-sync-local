# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149519");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 03:53:58 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 00:03:00 +0000 (Fri, 30 Jun 2023)");

  script_cve_id("CVE-2023-1707");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Information Disclosure Vulnerability (HPSBPI03838)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to an information disclosure
  vulnerability when IPSec is enabled with FutureSmart version 5.6.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_7905330-7905358-16/hpsbpi03838");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_5700_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040443")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040443 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m5800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m5800_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040428")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040428 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_6700_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_6701_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040413")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040413 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m6800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m6800_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040449")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040449 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m455_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038578")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038578 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m480_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038575")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038575 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e45028_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038578")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038578 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e45028_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038575")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038575 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e785dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78523_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78528_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038571")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038571 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e786_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78625_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78630_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78635_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038569")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038569 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e877_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e877[4567]0" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_e877[4567]0") {
  if (version_is_less(version: version, test_version: "2506421.038579")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038579 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_x55745_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040443")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040443 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_x57945_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_x57945_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040428")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040428 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m406_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_m407_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038580")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038580 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m430_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m431_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038573")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038573 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e40040_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038580")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038580 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e42540_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038573")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038573 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e730_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e73025_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e73030_firmware") {
  if (version_is_less(version: version, test_version: "2506421.038576")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038576 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e731_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m731_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e731(30|35|40)" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_e731(30|35|40)") {
  if (version_is_less(version: version, test_version: "2506421.038568")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038568 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e826dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e826z_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e826[567]0") {
  if (version_is_less(version: version, test_version: "2506421.038570")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506421_038570 (5.6.0.1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
