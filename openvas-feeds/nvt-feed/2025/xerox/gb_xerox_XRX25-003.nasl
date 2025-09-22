# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171146");
  script_version("2025-08-01T05:45:36+0000");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 19:26:58 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2024-12510", "CVE-2024-12511");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox Printers Multiple Vulnerabilities (XRX25-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Multiple Xerox printers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-12510: LDAP Authentication Server Pass-back

  - CVE-2024-12511: SMB/FTP Address Book Scan Pass-back");

  script_tag(name:"affected", value:"Xerox VersaLink, Phaser and WorkCentre printers.

  See the referenced vendor advisory for affected models.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2025/02/Xerox-Security-Bulletin-XRX25-003-for-Xerox%C2%AE-for-VersaLinkPhaser-and-WorkCentre.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:versalink_b400_firmware",
                     "cpe:/o:xerox:versalink_b405_firmware",
                     "cpe:/o:xerox:versalink_c400_firmware",
                     "cpe:/o:xerox:versalink_c405_firmware",
                     "cpe:/o:xerox:versalink_b600_firmware",
                     "cpe:/o:xerox:versalink_b610_firmware",
                     "cpe:/o:xerox:versalink_b605_firmware",
                     "cpe:/o:xerox:versalink_b615_firmware",
                     "cpe:/o:xerox:versalink_c500_firmware",
                     "cpe:/o:xerox:versalink_c600_firmware",
                     "cpe:/o:xerox:versalink_c505_firmware",
                     "cpe:/o:xerox:versalink_c605_firmware",
                     "cpe:/o:xerox:versalink_c7000_firmware",
                     "cpe:/o:xerox:versalink_c7020_firmware",
                     "cpe:/o:xerox:versalink_c7025_firmware",
                     "cpe:/o:xerox:versalink_c7030_firmware",
                     "cpe:/o:xerox:versalink_b7025_firmware",
                     "cpe:/o:xerox:versalink_b7030_firmware",
                     "cpe:/o:xerox:versalink_b7035_firmware",
                     "cpe:/o:xerox:versalink_b7125_firmware",
                     "cpe:/o:xerox:versalink_b7130_firmware",
                     "cpe:/o:xerox:versalink_b7135_firmware",
                     "cpe:/o:xerox:versalink_c7120_firmware",
                     "cpe:/o:xerox:versalink_c7125_firmware",
                     "cpe:/o:xerox:versalink_c7130_firmware",
                     "cpe:/o:xerox:versalink_c8000_firmware",
                     "cpe:/o:xerox:versalink_c9000_firmware",
                     "cpe:/o:xerox:versalink_c8000w_firmware",
                     "cpe:/o:xerox:phaser_6510_firmware",
                     "cpe:/o:xerox:workcentre_6515_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:xerox:versalink_b400_firmware") {
  if (version_is_less(version: version, test_version: "37.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "37.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_b405_firmware") {
  if (version_is_less(version: version, test_version: "38.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "38.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c400_firmware") {
  if (version_is_less(version: version, test_version: "67.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "67.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c405_firmware") {
  if (version_is_less(version: version, test_version: "68.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "68.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_b6[01]0_firmware") {
  if (version_is_less(version: version, test_version: "32.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "32.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_b6[01]5_firmware") {
  if (version_is_less(version: version, test_version: "33.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "33.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_c[56]00_firmware") {
  if (version_is_less(version: version, test_version: "61.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "61.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_c[56]05_firmware") {
  if (version_is_less(version: version, test_version: "62.82.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "62.82.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c7000_firmware") {
  if (version_is_less(version: version, test_version: "56.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "56.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_c70(20|25|30)_firmware") {
  if (version_is_less(version: version, test_version: "57.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "57.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_b70(25|30|35)_firmware") {
  if (version_is_less(version: version, test_version: "58.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "58.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_b71(25|30|35)_firmware") {
  if (version_is_less(version: version, test_version: "59.24.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "59.24.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_c71(20|25|30)_firmware") {
  if (version_is_less(version: version, test_version: "69.24.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "69.24.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:xerox:versalink_c[89]000_firmware") {
  if (version_is_less(version: version, test_version: "70.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "70.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c8000w_firmware") {
  if (version_is_less(version: version, test_version: "72.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "72.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:phaser_6510_firmware") {
  if (version_is_less(version: version, test_version: "64.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "64.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_6515_firmware") {
  if (version_is_less(version: version, test_version: "65.75.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "65.75.53");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
