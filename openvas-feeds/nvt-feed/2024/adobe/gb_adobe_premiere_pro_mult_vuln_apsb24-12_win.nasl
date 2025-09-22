# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:premiere_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832870");
  script_version("2024-05-03T05:05:25+0000");
  script_cve_id("CVE-2024-20745", "CVE-2024-20746");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-14 16:10:00 +0530 (Thu, 14 Mar 2024)");
  script_name("Adobe Premiere Pro Multiple Vulnerabilities (APSB24-12) - Windows");

  script_tag(name:"summary", value:"The Adobe Premiere Pro device is missing a
  security update announced via the apsb24-12 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-20745: Arbitrary code execution

  - CVE-2024-20746: Arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Premiere Pro versions 24.0 prior to 24.2.1
  and prior to 23.6.4.");

  script_tag(name:"solution", value:"Update to version 24.2.1 or 23.6.4 or
  later. See the referenced vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb24-12.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_pro_detect_win.nasl");
  script_mandatory_keys("adobe/premierepro/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_greater(version:vers, test_version:"23.6.4") && version_is_less_equal(version:vers, test_version:"24.1")) {
  fix = "24.2.1";
}

if(version_is_less(version:vers, test_version:"23.6.4")) {
  fix = "23.6.4";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
