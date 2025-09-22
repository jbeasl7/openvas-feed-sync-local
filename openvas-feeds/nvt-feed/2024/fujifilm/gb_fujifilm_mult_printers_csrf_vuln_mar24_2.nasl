# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170788");
  script_version("2024-05-21T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-05-21 05:05:23 +0000 (Tue, 21 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-17 08:19:34 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-22475");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fuji Xerox / Fujifilm Printers CSRF Vulnerability (CVE-2024-22475)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_fujifilm_printer_consolidation.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_tag(name:"summary", value:"Multiple Fuji Xerox / Fujifilm printers are prone to a cross-site
  request forgery (CSRF) vulnerability in the Web Based Management.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"If a user views a malicious page while logged in, unintended operations
  may be performed.");

  script_tag(name:"solution", value:"Update to fixed version and apply the mitigation steps where the case.
  See the referenced vendor advisory for further details.");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbglobal/eng/company/news/notice/2024/0306_2_announce.html");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82749078/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:fujifilm:docuprint_p378_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p375_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p375_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p378_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p385_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p388_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m378_d_firmware",
                     "cpe:/o:fujifilm:docuprint_m375_df_firmware",
                     "cpe:/o:fujifilm:docuprint_m378_df_firmware",
                     "cpe:/o:fujifilm:docuprint_m375_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m385_df_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe =~ "^cpe:/o:fujifilm:docuprint_p37[58]_(d|dw)_firmware") {
  if (version_is_less(version: version, test_version: "1.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.21");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_p38[58]_dw_firmware") {
  if (version_is_less(version: version, test_version: "1.19")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.19");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m378_(d|df)_firmware" ||
    cpe =~ "^cpe:/o:fujifilm:docuprint_m375_(df|z)_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:fujifilm:docuprint_m385_z_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);