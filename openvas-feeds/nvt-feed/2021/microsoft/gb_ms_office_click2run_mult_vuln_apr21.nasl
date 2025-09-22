# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817998");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2021-28451", "CVE-2021-28452", "CVE-2021-28453", "CVE-2021-28454",
                "CVE-2021-28456", "CVE-2021-28449");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 23:43:00 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-15 11:24:37 +0530 (Thu, 15 Apr 2021)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Apr 2021)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  Microsoft Office 365 (2016 Click-to-Run)");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and disclose sensitive information.");

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

## Version 2103 (Build 13901.20400)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13901.20400")){
    fix = "2103 (Build 13901.20400)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Version 2102 (Build 13801.20506)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13801.20506")){
    fix = "2102 (Build 13801.20506)";
  }
}

## Version 2008 (Build 13127.21506)
## Version 2002 (Build 12527.21814)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.21506")){
    fix = "2008 (Build 13127.21506)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.12527", test_version2:"16.0.12527.21813")){
    fix = "2002 (Build 12527.21814)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
