# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818535");
  script_version("2025-04-29T05:39:55+0000");
  script_cve_id("CVE-2021-39820", "CVE-2021-39821", "CVE-2021-39822", "CVE-2021-40727");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-24 00:29:20 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"creation_date", value:"2021-09-16 13:01:06 +0530 (Thu, 16 Sep 2021)");
  script_name("Adobe InDesign RCE Vulnerabilities (APSB21-73) - Windows");

  script_tag(name:"summary", value:"Adobe Indesign is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Access of Memory Location After End of Buffer.

  - Out-of-bounds Read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe InDesign 16.3 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 15.1.4, 16.4 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb21-73.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"15.1.4"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.1.4", install_path:path);
  security_message(data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"16.0", test_version2:"16.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.4", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
