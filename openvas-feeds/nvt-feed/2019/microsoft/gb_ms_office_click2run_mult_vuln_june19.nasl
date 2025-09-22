# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814982");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2019-1034", "CVE-2019-1035");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:08:00 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-06-12 13:56:47 +0530 (Wed, 12 Jun 2019)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple RCE Vulnerabilities (Jun 2019)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Microsoft Word software when it fails to properly handle
    objects in memory.

  - Multiple errors when the Microsoft Office Access Connectivity Engine
    improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"Upgrade to latest version of Microsoft Office
  365 (2016 Click-to-Run) with respect to update channel used. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108580");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

## 1905 (Build 11629.20246)
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11629.20246")){
    fix = "1905 (Build 11629.20246)";
  }
}

## 1902 (Build 11328.20318)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11328.20318")){
    fix = "1902 (Build 11328.20318)";
  }
}

## 1803 (Build 9126.2388)
## 1808 (Build 10730.20348)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.9126.2388")){
    fix = "1803 (Build 9126.2388)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.10730", test_version2:"16.0.10730.20347")){
    fix = "1808 (Build 10730.20348)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
