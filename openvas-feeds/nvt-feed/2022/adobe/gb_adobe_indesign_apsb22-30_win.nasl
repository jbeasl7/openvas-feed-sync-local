# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821131");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-30658", "CVE-2022-30659", "CVE-2022-30661", "CVE-2022-30662",
                "CVE-2022-30663", "CVE-2022-30665", "CVE-2022-30660", "CVE-2022-34245",
                "CVE-2022-34246", "CVE-2022-34248", "CVE-2022-34247");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 18:22:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-16 22:28:22 +0530 (Thu, 16 Jun 2022)");
  script_name("Adobe InDesign RCE Vulnerabilities (APSB22-30) - Windows");

  script_tag(name:"summary", value:"Adobe Indesign is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple heap-based buffer overflow.

  - Multiple out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Adobe InDesign 17.2.1 and earlier versions,
  16.4.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 17.3 or
  16.4.2 or later.Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb22-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.2.1")) {
  fix = "17.3";
}

if (version_in_range(version: vers, test_version: "16.0.0", test_version2: "16.4.1")) {
  fix = "16.4.2";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
