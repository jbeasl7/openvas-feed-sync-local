# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:animate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832872");
  script_version("2024-05-03T05:05:25+0000");
  script_cve_id("CVE-2024-20761", "CVE-2024-20762", "CVE-2024-20763", "CVE-2024-20764");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 18:15:08 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-14 16:10:00 +0530 (Thu, 14 Mar 2024)");
  script_name("Adobe Animate Multiple Vulnerabilities (APSB24-19) - Windows");

  script_tag(name:"summary", value:"The Adobe Animate device is missing a
  security update announced via the apsb24-17 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-20761: Arbitrary code execution

  - CVE-2024-20762: Memory leak

  - Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct memory leak attack and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Animate 2023 versions prior to
  23.0.4 and 2024 versions prior to 24.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Animate 2023 to 23.0.4 or
  later, 2024 to 24.0.1 or later. See the referenced vendor advisory for a
  solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb24-19.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_animate_detect_win.nasl");
  script_mandatory_keys("Adobe/Animate/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_greater(version:vers, test_version:"23.0.4") && version_is_less_equal(version:vers, test_version:"24.0")) {
  fix = "24.0.1";
}

if(version_is_less(version:vers, test_version:"23.0.4")) {
  fix = "23.0.4";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
