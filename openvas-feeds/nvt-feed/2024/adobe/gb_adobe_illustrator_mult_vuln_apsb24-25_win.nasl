# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832937");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2024-30271", "CVE-2024-30272", "CVE-2024-30273", "CVE-2024-20798");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-11 18:15:07 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 16:14:00 +0530 (Mon, 15 Apr 2024)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB24-25) - Windows");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30271: out-of-bounds write error

  - CVE-2024-20798: out-of-bounds read error

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code and cause memory leak.");

  script_tag(name:"affected", value:"Adobe Illustrator 2023 prior to 27.9.3 and
  Adobe Illustrator 2024 prior to 28.4 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Illustrator 2023 to version
  27.9.3 or Adobe Illustrator 2024 to version 28.4 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb24-25.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_win.nasl");
  script_mandatory_keys("Adobe/Illustrator/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^27\.") {
  if(version_is_less(version:vers, test_version:"27.9.3")) {
    fix = "27.9.3";
    installed_ver = "Adobe Illustrator 2023";
  }
}

else if(vers =~ "^28\.") {
  if(version_is_less(version:vers, test_version:"28.4")) {
    fix = "28.4";
    installed_ver = "Adobe Illustrator 2024";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
