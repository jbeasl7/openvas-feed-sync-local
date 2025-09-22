# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832932");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2024-20770");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-10 13:51:38 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-11 17:02:00 +0530 (Thu, 11 Apr 2024)");
  script_name("Adobe Photoshop Memory leak Vulnerability (APSB24-16) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to a Memory leak
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause a memory leak.");

  script_tag(name:"affected", value:"Adobe Photoshop 2023 prior to 24.7.3 and
  Adobe Photoshop 2024 prior to 25.4.");

  script_tag(name:"solution", value:"Update Adobe Photoshop 2023 to 24.7.3 or
  later and Adobe Photoshop 2024 to 25.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb24-16.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^25\.") {
  if(version_is_less(version:vers, test_version:"25.4")) {
    fix = "25.4";
    installed_ver = "Adobe Photoshop 2024";
  }
}
else if(vers =~ "^24\.") {
  if(version_is_less(version:vers, test_version:"24.7.3")) {
    fix = "24.7.3";
    installed_ver = "Adobe Photoshop 2023";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
