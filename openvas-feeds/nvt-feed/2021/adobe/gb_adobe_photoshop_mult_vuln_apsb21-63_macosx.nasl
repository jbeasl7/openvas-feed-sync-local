# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818188");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2021-36005", "CVE-2021-36006");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 14:46:00 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-12 13:09:23 +0530 (Thu, 12 Aug 2021)");
  script_name("Adobe Photoshop Multiple Vulnerabilities (APSB21-63) - Mac OS X");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe August update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper input validation error.

  - A stack-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and read arbitrary files on an affected system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2020 prior to 21.2.10 and
  Adobe Photoshop 2021 prior to 22.4.3 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop 2020 21.2.10
  or Photoshop 2021 22.4.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-63.html");

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^21\.") {
  if(version_is_less(version:vers, test_version:"21.2.10")) {
    fix = "21.2.10";
    installed_ver = "Adobe Photoshop 2020";
  }
}

else if(vers =~ "^22\.") {
  if(version_is_less(version:vers, test_version:"22.4.3")) {
    fix = "22.4.3";
    installed_ver = "Adobe Photoshop 2021";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
