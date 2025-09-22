# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820001");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2022-23203");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 15:26:00 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 14:18:31 +0530 (Thu, 10 Feb 2022)");
  script_name("Adobe Photoshop RCE Vulnerability (APSB22-08) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution on target system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2021 prior to 22.5.5 and
  Adobe Photoshop 2022 prior to 23.1.1.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2021 22.5.5
  or Adobe Photoshop 2022 23.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-08.html");

  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(vers =~ "^22\.")
{
  if(version_is_less(version:vers, test_version:"22.5.5")) {
    fix = "22.5.5";
    installed_ver = "Adobe Photoshop CC 2021";
  }
}

else if(vers =~ "^23\.")
{
  if(version_is_less(version:vers, test_version:"23.1.1"))
  {
    fix = "23.1.1";
    installed_ver = "Adobe Photoshop CC 2022";
  }
}
if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
