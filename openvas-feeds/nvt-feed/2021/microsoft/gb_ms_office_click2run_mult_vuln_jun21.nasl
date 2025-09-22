# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818322");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2021-28455", "CVE-2021-31939", "CVE-2021-31949", "CVE-2021-31941",
                "CVE-2021-31940");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 23:15:00 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Jun 2021)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  Microsoft Office 365 (2016 Click-to-Run)");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");
  script_tag(name:"qod_type", value:"registry");
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

##  2105 (Build 14026.20270)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14026.20270")){
    fix = "2105 (Build 14026.20270)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## 2102 (Build 13801.20738)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13801.20738")){
    fix = "2102 (Build 13801.20738)";
  }
}

## 2008 (Build 13127.21668)
## 2002 (Build 12527.21952)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.21668")){
    fix = "2008 (Build 13127.21668)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.12527", test_version2:"16.0.12527.21951")){
    fix = "2002 (Build 12527.21952)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
