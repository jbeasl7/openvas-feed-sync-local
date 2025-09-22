# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833919");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-20791", "CVE-2024-20792", "CVE-2024-20793");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-16 09:15:09 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-16 14:36:54 +0530 (Thu, 16 May 2024)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB24-30) - Windows");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-20791: out-of-bounds write error

  - CVE-2024-20793: out-of-bounds read error

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code and cause memory leak.");

  script_tag(name:"affected", value:"Adobe Illustrator 2023 prior to 27.9.4 and
  Adobe Illustrator 2024 prior to 28.5 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Illustrator 2023 to version
  27.9.4 or Adobe Illustrator 2024 to version 28.5 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb24-30.html");
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
  if(version_is_less(version:vers, test_version:"27.9.4")) {
    fix = "27.9.4";
    installed_ver = "Adobe Illustrator 2023";
  }
}

else if(vers =~ "^28\.") {
  if(version_is_less(version:vers, test_version:"28.5")) {
    fix = "28.5";
    installed_ver = "Adobe Illustrator 2024";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
