# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818929");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2021-43256", "CVE-2021-42293", "CVE-2021-43875", "CVE-2021-42295",
                "CVE-2021-43255");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-23 18:39:00 +0000 (Thu, 23 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-15 15:57:04 +0530 (Wed, 15 Dec 2021)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Dec 2021)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run updates");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An information disclosure vulnerability in Visual Basic for Applications.

  - A spoofing vulnerability in Microsoft Office Trust Center.

  - A remote code execution vulnerability Microsoft Office Graphics.

  - An elevation of privilege vulnerability in Microsoft Jet Red Database Engine and Access Connectivity Engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, conduct spoofing attacks, disclose sensitive information
  and conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2111 (Build 14701.20248)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14701.20248")){
    fix = "2111 (Build 14701.20248)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2108 (Build 14326.20692)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14326.20692")){
    fix = "2108 (Build 14326.20692)";
  }
}

## Semi-Annual Enterprise Channel: Version 2102 (Build 13801.21086)
## Semi-Annual Enterprise Channel: Version 2008 (Build 13127.21842)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.21842")){
    fix = "2008 (Build 13127.21842)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.13801", test_version2:"16.0.13801.21085")){
    fix = "2002 (Build 12527.22017)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
