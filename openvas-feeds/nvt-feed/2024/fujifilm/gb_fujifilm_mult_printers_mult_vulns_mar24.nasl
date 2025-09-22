# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170789");
  script_version("2024-05-21T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-05-21 05:05:23 +0000 (Tue, 21 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-17 08:19:34 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-21824", "CVE-2024-22475");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fuji Xerox / Fujifilm Printers Multiple Vulnerabilities (Mar 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_fujifilm_printer_consolidation.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_tag(name:"summary", value:"Multiple Fuji Xerox / Fujifilm printers are prone to multiple
  vulnerabilities in the Web Based Management.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-21824: Improper authentication

  - CVE-2024-22475: cross-site request forgery (CSRF)");

  script_tag(name:"solution", value:"Update to fixed version and apply the mitigation steps where the case.
  See the referenced vendor advisory for further details.");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbglobal/eng/company/news/notice/2024/0306_2_announce.html");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82749078/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:fujifilm:docuprint_p235_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p275_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p285_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p288_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m235_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m235_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m275_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m285_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m288_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m288_z_firmware",
                     "cpe:/o:fujifilm:docuprint_p225_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p268_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p265_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m268_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m268_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m225_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m225_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m265_z_firmware",
                     "cpe:/o:fujifilm:docuprint_p118_w_firmware",
                     "cpe:/o:fujifilm:docuprint_p115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m118_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m118_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_fw_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_z_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:fujifilm:docuprint_p235_d_firmware" ||
    cpe =~ "^cpe:/o:fujifilm:docuprint_p2[78]5_dw_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_p288_dw_firmware") {
  if (version_is_less(version: version, test_version: "1.15")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.15");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m235_(dw|z)_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m2[78]5_z_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m288_(dw|z)_firmware") {
  if (version_is_less(version: version, test_version: "E")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "E");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_p268_(d|dw)_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_p265_dw_firmware") {
  if (version_is_less(version: version, test_version: "1.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.22");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m268_(dw|z)_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m225_(dw|z)_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_m265_z_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_p11[58]_w_firmware") {
  if (version_is_less(version: version, test_version: "1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m11[58]_(w|z)_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_m115_fw_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);