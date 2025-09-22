# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826462");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-28851", "CVE-2022-28852", "CVE-2022-28853", "CVE-2022-28854",
                "CVE-2022-28855", "CVE-2022-28856", "CVE-2022-28857", "CVE-2022-30671",
                "CVE-2022-30672", "CVE-2022-30673", "CVE-2022-30674", "CVE-2022-30675",
                "CVE-2022-30676", "CVE-2022-38413", "CVE-2022-38414", "CVE-2022-38415",
                "CVE-2022-38416", "CVE-2022-38417");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-20 15:19:00 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-15 11:33:35 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe InDesign Multiple Vulnerabilities (APSB22-50) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Indesign is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple Heap-based Buffer Overflow.

  - Multiple out-of-bounds write error.

  - Improper Input Validation.

  - Multiple Out-of-bounds Read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and memory leak on the system.");

  script_tag(name:"affected", value:"Adobe InDesign 17.3 and earlier versions,
  16.4.2 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 17.4 or
  16.4.3 or later.Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb22-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_indesign_server_detect_macosx.nasl");
  script_mandatory_keys("InDesign/Server/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.3")) {
  fix = "17.4";
}

if (version_in_range(version: vers, test_version: "16.0", test_version2: "16.4.2")) {
  fix = "16.4.3";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
