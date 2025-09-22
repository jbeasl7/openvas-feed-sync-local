# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820040");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2021-40481", "CVE-2021-40480");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 23:15:00 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2022-03-28 12:12:50 +0530 (Mon, 28 Mar 2022)");
  script_name("Microsoft Office 365 (2019 Click-to-Run) Multiple RCE Vulnerabilities (Oct 2021)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper validation of user-supplied data when parsing EMF files in
    Microsoft Office Visio.

  - A use-after-free error when parsing WMF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to compromise the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2019 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

officeRel = get_kb_item("MS/Off/C2R/Release");
if(!officeRel || "2019" >!< officeRel){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2109 (Build 14430.20298)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14430.20298")){
    fix = "Version 2109 (Build 14430.20298)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2108 (Build 14326.20508)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14326.20508")){
    fix = "Version 2108 (Build 14326.20508)";
  }
}

##Semi-Annual Enterprise Channel: Version 2102 (Build 13801.21004)
##Semi-Annual Enterprise Channel: Version 2008 (Build 13127.21792)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.21792")){
    fix = "Version 2008 (Build 13127.21792)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.13801", test_version2:"16.0.13801.21003")){
    fix = "Version 2102 (Build 13801.21004)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
