# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834547");
  script_version("2025-03-07T15:40:19+0000");
  script_cve_id("CVE-2024-49142", "CVE-2024-49069", "CVE-2024-49065", "CVE-2024-49059");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 02:04:40 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 11:34:17 +0530 (Wed, 11 Dec 2024)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Dec 2024)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Office Click-to-Run update December 2024.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-49142: Microsoft Access Remote Code Execution Vulnerability

  - CVE-2024-49069: Microsoft Excel Remote Code Execution Vulnerability

  - CVE-2024-49065: Microsoft Office Remote Code Execution Vulnerability

  - CVE-2024-49059: Microsoft Office Elevation of Privilege Vulnerability

  - ADV240002: Microsoft Office Defense in Depth Update");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to conduct
  remote code execution and privilege escalation.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\.")
  exit(0);

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2411 (Build 18227.20162)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.18227.20162"))
    fix = "Version 2411 (Build 18227.20162)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2408 (Build 17928.20336)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.17928.20336"))
    fix = "Version 2408 (Build 17928.20336)";
}

## Semi-Annual Enterprise Channel: Version 2402 (Build 17328.20670)
## Semi-Annual Enterprise Channel: Version 2308 (Build 16731.20998)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.16731.0", test_version2:"16.0.16731.20997")) {
    fix = "Version 2308 (Build 16731.20998)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.17328.0", test_version2:"16.0.17328.20669")) {
      fix = "Version 2402 (Build 17328.20670)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
