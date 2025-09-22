# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:laserjet";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171657");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-01 13:31:50 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-9423");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Color LaserJet Printers DoS Vulnerability (HPSBPI04040)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP LaserJet Pro printers are prone to a denial of
  service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet printers may potentially experience a
  denial of service when a user sends a raw JPEG file to the printer. The printer displays a 'JPEG
  Unsupported' message which may not clear, potentially blocking queued print jobs.");

  script_tag(name:"affected", value:"Certain HP LaserJet and LaserJet Tank Printers (see the
  referenced vendor advisory for a complete list) prior to version 20240813.");

  script_tag(name:"solution", value:"Update to version 20240813 or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_11266441-11266463-16/hpsbpi03976");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];
# nb: It seems that when the advisory mentions LaserJet MFP M139 - M142 Printer series, it can be eg M140
if (cpe !~ "^cpe:/o:hp:laserjet_mfp_m23[2-7]" &&
    cpe !~ "^cpe:/o:hp:laserjet_m20[7-9]" &&
    cpe !~ "^cpe:/o:hp:laserjet_m21[0-2]" &&
    cpe !~ "^cpe:/o:hp:laserjet_mfp_m139" &&
    cpe !~ "^cpe:/o:hp:laserjet_mfp_m14[0-2]" &&
    cpe !~ "^cpe:/o:hp:laserjet_m109" &&
    cpe !~ "^cpe:/o:hp:laserjet_m11[0-2]" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_mfp_1005" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_mfp_[12]60[2-4]" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_mfp_260[56]" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_[12]50[2-4]" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_250[56]" &&
    cpe !~ "^cpe:/o:hp:laserjet_tank_1020")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "20240813")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20240813");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
