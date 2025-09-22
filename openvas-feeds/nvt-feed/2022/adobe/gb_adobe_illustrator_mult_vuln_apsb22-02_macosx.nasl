# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819945");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2021-43752", "CVE-2021-44700");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 16:01:00 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 18:57:40 +0530 (Thu, 13 Jan 2022)");
  script_name("Adobe Illustrator Multiple Privilege Escalation Vulnerabilities (APSB22-02) - Mac OS X");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe January update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple out-of-bounds read errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct privilege escalation on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator 2021 25.4.2 and earlier,
  2022 26.x prior to 26.0.2 versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator 2021 version
  25.4.3 or 26.0.2 or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-02.html");
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"25.4.3")){
  fix = "25.4.3";
} else if(version_in_range(version:vers, test_version:"26.0", test_version2:"26.0.1")){
    fix = "26.0.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
