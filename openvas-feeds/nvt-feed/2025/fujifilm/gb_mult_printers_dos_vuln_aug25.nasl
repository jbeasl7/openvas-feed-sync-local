# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171662");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-06 13:00:01 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2025-48499");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Fuji Xerox / Fujifilm Printers DoS Vulnerability (Aug 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_fujifilm_printer_consolidation.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_tag(name:"summary", value:"Multiple Fuji Xerox / Fujifilm printers are prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"The printer may freeze when some specific IPP and LPD protocol
  packets are processed. The issue arises during data writing process in the buffer memory on the
  printer. There is a possibility of failing to validate the length of the data in the existing
  logic. When data of certain length is received, the data may be written beyond the specified
  buffer area.");

  script_tag(name:"solution", value:"Update the firmware to the fixed version. See the referenced
  advisory for additional details.");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbglobal/eng/company/news/notice/2025/0804_announce.html");
  script_xref(name:"URL", value:"https://jvn.jp/en/vu/JVNVU93897456/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:fujifilm:docuprint_cp225_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cp228_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cp115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cp118_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cp116_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cp119_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cm225_fw_firmware",
                     "cpe:/o:fujifilm:docuprint_cm228_fw_firmware",
                     "cpe:/o:fujifilm:docuprint_cm115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_cm118_w_firmware",
                     "cpe:/o:fujifilm:apeos_2150_n_firmware",
                     "cpe:/o:fujifilm:apeos_2350_nda_firmware",
                     "cpe:/o:fujifilm:apeos_2150_nd_firmware",
                     "cpe:/o:fujifilm:apeos_2150_nda_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:fujifilm:docuprint_cp22[58]_w_firmware") {
  if (version_is_less(version: version, test_version: "01.24.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "01.24.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_cp11[5689]_w_firmware" ||
    cpe =~ "^cpe:/o:fujifilm:docuprint_cm11[58]_w_firmware") {
  if (version_is_less(version: version, test_version: "01.11.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "01.11.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_cm22[58]_fw_firmware") {
  if (version_is_less(version: version, test_version: "01.13.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "01.13.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:apeos_2350_nda_firmware" ||
    cpe =~ "^cpe:/o:fujifilm:apeos_2150_(n|nd|nda)_firmware") {
  if (version_is_less(version: version, test_version: "01.20.50")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "01.20.50");
    security_message(port: 0, data: report);
    exit(0);
  }
}