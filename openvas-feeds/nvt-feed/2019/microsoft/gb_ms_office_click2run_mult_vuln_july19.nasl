# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815167");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2019-1084", "CVE-2019-1109", "CVE-2019-1110", "CVE-2019-1111",
                "CVE-2019-1112");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-11 09:58:50 +0530 (Thu, 11 Jul 2019)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Jul 2019)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Microsoft Exchange allows creation of entities with Display
    Names having non-printable characters.

  - An error when Microsoft Office Javascript does not check the validity of the
    web page making a request to Office documents.

  - Multiple errors in Microsoft Excel because it fails to properly handle objects in memory.

  - An error when Microsoft Excel improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user, read or write information
  in Office documents and gain access to sensitive data.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108974");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108975");

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

## 1906 (Build 11727.20244)
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11727.20244")){
    fix = "1906 (Build 11727.20244)";
  }
}

## 1902 (Build 11328.20368)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11328.20368")){
    fix = "1902 (Build 11328.20368)";
  }
}

## 1902 (Build 11328.20368)
## 1808 (Build 10730.20360)
## 1803 (Build 9126.2428)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.9126.2428")){
    fix = "1803 (Build 9126.2428)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.10730", test_version2:"16.0.10730.20359")){
    fix = "1808 (Build 10730.20360)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.11328", test_version2:"16.0.11328.20367")){
    fix = "1902 (Build 11328.20368)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
