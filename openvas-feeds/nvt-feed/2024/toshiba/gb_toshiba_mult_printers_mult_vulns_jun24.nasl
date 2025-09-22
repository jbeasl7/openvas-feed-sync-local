# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170791");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-08 20:41:07 +0000 (Mon, 08 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-3496", "CVE-2024-3498", "CVE-2024-27141", "CVE-2024-27142",
                "CVE-2024-27143", "CVE-2024-27144", "CVE-2024-27145", "CVE-2024-27146",
                "CVE-2024-27147", "CVE-2024-27148", "CVE-2024-27149", "CVE-2024-27150",
                "CVE-2024-27151", "CVE-2024-27152", "CVE-2024-27153", "CVE-2024-27154",
                "CVE-2024-27155", "CVE-2024-27156", "CVE-2024-27157", "CVE-2024-27158",
                "CVE-2024-27159", "CVE-2024-27160", "CVE-2024-27161", "CVE-2024-27162",
                "CVE-2024-27163", "CVE-2024-27164", "CVE-2024-27165", "CVE-2024-27166",
                "CVE-2024-27167", "CVE-2024-27168", "CVE-2024-27169", "CVE-2024-27170",
                "CVE-2024-27171", "CVE-2024-27172", "CVE-2024-27173", "CVE-2024-27174",
                "CVE-2024-27175", "CVE-2024-27176", "CVE-2024-27177", "CVE-2024-27178",
                "CVE-2024-27179", "CVE-2024-27180");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Toshiba Printers Multiple Vulnerabilities (May 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_toshiba_printer_consolidation.nasl");
  script_mandatory_keys("toshiba/printer/detected");

  script_tag(name:"summary", value:"Multiple Toshiba printers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target
  host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-27141, CVE-2024-27142: XML entity expansion (XEE)

  - CVE-2024-27143, CVE-2024-27146, CVE-2024-27147, CVE-2024-3498: Execution with unnecessary
  privileges

  - CVE-2024-27148, CVE-2024-27149, CVE-2024-27150, CVE-2024-27151, CVE-2024-27152, CVE-2024-27153,
  CVE-2024-27155, CVE-2024-27167, CVE-2024-27171: Incorrect default permissions

  - CVE-2024-27144, CVE-2024-27145, CVE-2024-27173, CVE-2024-27174, CVE-2024-27176, CVE-2024-27177,
  CVE-2024-27178: Path traversal

  - CVE-2024-27154, CVE-2024-27156, CVE-2024-27157: Insertion of sensitive information into log file

  - CVE-2024-27166: Plaintext storage of a password

  - CVE-2024-27179: Debug messages revealing unnecessary information

  - CVE-2024-27158: Use of default credentials

  - CVE-2024-27159, CVE-2024-27160, CVE-2024-27161, CVE-2024-27168, CVE-2024-27170: Use of
  hard-coded credentials

  - CVE-2024-27164: Use of hard-coded password

  - CVE-2024-27162: cross-site scripting (XSS)

  - CVE-2024-27163: Cleartext transmission of sensitive information

  - CVE-2024-27165: Least privilege violation

  - CVE-2024-27169: Missing authentication for critical function

  - CVE-2024-27172: OS command injection

  - CVE-2024-27175: External control of file name or path

  - CVE-2024-27180: Time-of-check time-of-use (TOCTOU) race condition

  - CVE-2024-3496: Authentication bypass using an alternate path or channel");

  script_tag(name:"solution", value:"Update to fixed version and apply the mitigation steps where
  the case. See the referenced vendor advisory for further details.");

  script_xref(name:"URL", value:"https://www.toshibatec.com/information/20240531_01.html");
  script_xref(name:"URL", value:"https://jvn.jp/en//vu/JVNVU97136265/");
  script_xref(name:"URL", value:"https://jvn.jp/en/vu/JVNVU97136265/480298/index.html");
  script_xref(name:"URL", value:"https://pierrekim.github.io/advisories/2024-toshiba-mfp.txt");
  script_xref(name:"URL", value:"https://pierrekim.github.io/blog/2024-06-27-toshiba-mfp-40-vulnerabilities.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:toshibatec:e-studio2020ac_firmware",
                     "cpe:/o:toshibatec:e-studio2520ac_firmware",
                     "cpe:/o:toshibatec:e-studio2021ac_firmware",
                     "cpe:/o:toshibatec:e-studio2521ac_firmware",
                     "cpe:/o:toshibatec:e-studio2025nc_firmware",
                     "cpe:/o:toshibatec:e-studio2525ac_firmware",
                     "cpe:/o:toshibatec:e-studio3025ac_firmware",
                     "cpe:/o:toshibatec:e-studio3525ac_firmware",
                     "cpe:/o:toshibatec:e-studio3525acg_firmware",
                     "cpe:/o:toshibatec:e-studio4525ac_firmware",
                     "cpe:/o:toshibatec:e-studio4525acg_firmware",
                     "cpe:/o:toshibatec:e-studio5525ac_firmware",
                     "cpe:/o:toshibatec:e-studio5525acg_firmware",
                     "cpe:/o:toshibatec:e-studio6525ac_firmware",
                     "cpe:/o:toshibatec:e-studio6525acg_firmware",
                     "cpe:/o:toshibatec:e-studio2528a_firmware",
                     "cpe:/o:toshibatec:e-studio3028a_firmware",
                     "cpe:/o:toshibatec:e-studio3528ag_firmware",
                     "cpe:/o:toshibatec:e-studio4528a_firmware",
                     "cpe:/o:toshibatec:e-studio4528ag_firmware",
                     "cpe:/o:toshibatec:e-studio5528a_firmware",
                     "cpe:/o:toshibatec:e-studio6528a_firmware",
                     "cpe:/o:toshibatec:e-studio6526ac_firmware",
                     "cpe:/o:toshibatec:e-studio6527ac_firmware",
                     "cpe:/o:toshibatec:e-studio7527ac_firmware",
                     "cpe:/o:toshibatec:e-studio6529a_firmware",
                     "cpe:/o:toshibatec:e-studio7529a_firmware",
                     "cpe:/o:toshibatec:e-studio9029a_firmware",
                     "cpe:/o:toshibatec:e-studio330ac_firmware",
                     "cpe:/o:toshibatec:e-studio400ac_firmware",
                     "cpe:/o:toshibatec:e-studio2010ac_firmware",
                     "cpe:/o:toshibatec:e-studio2110ac_firmware",
                     "cpe:/o:toshibatec:e-studio2510ac_firmware",
                     "cpe:/o:toshibatec:e-studio2610ac_firmware",
                     "cpe:/o:toshibatec:e-studio2015nc_firmware",
                     "cpe:/o:toshibatec:e-studio2515ac_firmware",
                     "cpe:/o:toshibatec:e-studio2615ac_firmware",
                     "cpe:/o:toshibatec:e-studio3015ac_firmware",
                     "cpe:/o:toshibatec:e-studio3115ac_firmware",
                     "cpe:/o:toshibatec:e-studio3515ac_firmware",
                     "cpe:/o:toshibatec:e-studio3615ac_firmware",
                     "cpe:/o:toshibatec:e-studio4515ac_firmware",
                     "cpe:/o:toshibatec:e-studio4615ac_firmware",
                     "cpe:/o:toshibatec:e-studio5015ac_firmware",
                     "cpe:/o:toshibatec:e-studio5115ac_firmware",
                     "cpe:/o:toshibatec:e-studio2018a_firmware",
                     "cpe:/o:toshibatec:e-studio2518a_firmware",
                     "cpe:/o:toshibatec:e-studio2618a_firmware",
                     "cpe:/o:toshibatec:e-studio3018ag_firmware",
                     "cpe:/o:toshibatec:e-studio3618a_firmware",
                     "cpe:/o:toshibatec:e-studio3518ag_firmware",
                     "cpe:/o:toshibatec:e-studio3618ag_firmware",
                     "cpe:/o:toshibatec:e-studio4518a_firmware",
                     "cpe:/o:toshibatec:e-studio4618a_firmware",
                     "cpe:/o:toshibatec:e-studio4518ag_firmware",
                     "cpe:/o:toshibatec:e-studio4618ag_firmware",
                     "cpe:/o:toshibatec:e-studio5018a_firmware",
                     "cpe:/o:toshibatec:e-studio5118a_firmware",
                     "cpe:/o:toshibatec:e-studio5516ac_firmware",
                     "cpe:/o:toshibatec:e-studio5616ac_firmware",
                     "cpe:/o:toshibatec:e-studio6516ac_firmware",
                     "cpe:/o:toshibatec:e-studio6616ac_firmware",
                     "cpe:/o:toshibatec:e-studio7516ac_firmware",
                     "cpe:/o:toshibatec:e-studio7616ac_firmware",
                     "cpe:/o:toshibatec:e-studio5518a_firmware",
                     "cpe:/o:toshibatec:e-studio5618a_firmware",
                     "cpe:/o:toshibatec:e-studio6518a_firmware",
                     "cpe:/o:toshibatec:e-studio6618a_firmware",
                     "cpe:/o:toshibatec:e-studio7518a_firmware",
                     "cpe:/o:toshibatec:e-studio7618a_firmware",
                     "cpe:/o:toshibatec:e-studio8518a_firmware",
                     "cpe:/o:toshibatec:e-studio8618a_firmware",
                     "cpe:/o:toshibatec:e-studio2000ac_firmware",
                     "cpe:/o:toshibatec:e-studio2500ac_firmware",
                     "cpe:/o:toshibatec:e-studio2005nc_firmware",
                     "cpe:/o:toshibatec:e-studio2505ac_firmware",
                     "cpe:/o:toshibatec:e-studio3005ac_firmware",
                     "cpe:/o:toshibatec:e-studio3505ac_firmware",
                     "cpe:/o:toshibatec:e-studio4505ac_firmware",
                     "cpe:/o:toshibatec:e-studio5005ac_firmware",
                     "cpe:/o:toshibatec:e-studio2008a_firmware",
                     "cpe:/o:toshibatec:e-studio2508a_firmware",
                     "cpe:/o:toshibatec:e-studio3008a_firmware",
                     "cpe:/o:toshibatec:e-studio3008ag_firmware",
                     "cpe:/o:toshibatec:e-studio3508a_firmware",
                     "cpe:/o:toshibatec:e-studio3508ag_firmware",
                     "cpe:/o:toshibatec:e-studio4508a_firmware",
                     "cpe:/o:toshibatec:e-studio4508ag_firmware",
                     "cpe:/o:toshibatec:e-studio5008a_firmware",
                     "cpe:/o:toshibatec:e-studio5506ac_firmware",
                     "cpe:/o:toshibatec:e-studio6506ac_firmware",
                     "cpe:/o:toshibatec:e-studio7506ac_firmware",
                     "cpe:/o:toshibatec:e-studio5508a_firmware",
                     "cpe:/o:toshibatec:e-studio6508a_firmware",
                     "cpe:/o:toshibatec:e-studio7508a_firmware",
                     "cpe:/o:toshibatec:e-studio8508a_firmware",
                     "cpe:/o:toshibatec:e-studio3508lp_firmware",
                     "cpe:/o:toshibatec:e-studio4508lp_firmware",
                     "cpe:/o:toshibatec:e-studio5508lp_firmware",
                     "cpe:/o:toshibatec:e-studiolp35_firmware",
                     "cpe:/o:toshibatec:e-studiolp45_firmware",
                     "cpe:/o:toshibatec:e-studiolp50_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe =~ "^cpe:/o:toshibatec:e-studio2[05]2[01]ac_firmware" ||
    cpe == "cpe:/o:toshibatec:e-studio2025nc_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio(25|30)25ac_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[3456]525(ac|acg)_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio(25|30|45|55|65)28a_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[34]528ag_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio652[67]ac_firmware" ||
    cpe == "cpe:/o:toshibatec:e-studio7527ac_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio(65|75|90)29a_firmware") {
  if (version_is_less(version: version, test_version: "TS20SD0W1814")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TS20SD0W1814");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio(33|40)0ac_firmware") {
  if (version_is_less(version: version, test_version: "TP01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TP01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio2[0156]10ac_firmware") {
  if (version_is_less(version: version, test_version: "TB01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TB01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:toshibatec:e-studio2015nc_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[234][56]15ac_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[35][01]15ac_firmware") {
  if (version_is_less(version: version, test_version: "TC01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TC01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio2[056]18a_firmware" ||
    cpe == "cpe:/o:toshibatec:e-studio3018ag_firmware" ||
    cpe == "cpe:/o:toshibatec:e-studio3618a_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[34][56]18ag_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio4[56]18a_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio5[01]18a_firmware") {
  if (version_is_less(version: version, test_version: "TG01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TG01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio[567][56]16ac_firmware") {
  if (version_is_less(version: version, test_version: "TE01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TE01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio[5678][56]18a_firmware") {
  if (version_is_less(version: version, test_version: "TJ01HD0W2100")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TJ01HD0W2100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio2[05]00ac_firmware") {
  if (version_is_less(version: version, test_version: "T370HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T370HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:toshibatec:e-studio2005nc_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[234]505ac_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio[35]005ac_firmware") {
  if (version_is_less(version: version, test_version: "T373HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T373HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio(20|25|50)08a_firmware" ||
    cpe =~ "^cpe:/o:toshibatec:e-studio(30|35|45)08(a|ag)_firmware") {
  if (version_is_less(version: version, test_version: "T410HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T410HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio[567]506ac_firmware") {
  if (version_is_less(version: version, test_version: "T380HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T380HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio[5678]508a_firmware") {
  if (version_is_less(version: version, test_version: "T385HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T385HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studio[345]508lp_firmware") {
  if (version_is_less(version: version, test_version: "T430HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T430HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:toshibatec:e-studiolp(35|45|50)_firmware") {
  if (version_is_less(version: version, test_version: "T430HD0W1910")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T430HD0W1910");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);