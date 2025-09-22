# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836244");
  script_version("2025-08-15T15:42:26+0000");
  script_cve_id("CVE-2025-53731", "CVE-2025-53732", "CVE-2025-53740", "CVE-2025-53766",
                "CVE-2025-53733", "CVE-2025-53736", "CVE-2025-53738", "CVE-2025-53784",
                "CVE-2025-53735", "CVE-2025-53737", "CVE-2025-53739", "CVE-2025-53741",
                "CVE-2025-53759", "CVE-2025-53761", "CVE-2025-53730", "CVE-2025-53734");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 18:15:45 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-13 06:04:13 +0000 (Wed, 13 Aug 2025)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Aug 2025)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Office Click-to-Run update August 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to conduct
  remote code execution and information disclosure.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

## Version 2506 (Build 18925.20158)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Version 2507 (Build 19029.20184)") {
  if(version_is_less(version:officeVer, test_version:"16.0.19029.20184"))
    fix = "Version 2507 (Build 19029.20184)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2502 (Build 18526.20546)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.18526.20546"))
    fix = "Version 2502 (Build 18526.20546)";
}

## Semi-Annual Enterprise Channel: Version 2502 (Build 18526.20546)
## Semi-Annual Enterprise Channel: Version 2408 (Build 17928.20654)
## Semi-Annual Enterprise Channel: Version 2402 (Build 17328.20882)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.17328.0", test_version2:"16.0.17328.20881")) {
    fix = "Version 2402 (Build 17328.20882)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.17928.0", test_version2:"16.0.17928.20653")) {
      fix = "Version 2408 (Build 17928.20654)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18526.0", test_version2:"16.0.18526.20545")) {
      fix = "Version 2502 (Build 18526.20546)";
  }
}

## Monthly Enterprise Channel: Version 2506 (Build 18925.20216)
## Monthly Enterprise Channel: Version 2505 (Build 18827.20230)
## Monthly Enterprise Channel: Version 2504 (Build 18730.20260)
else if(UpdateChannel == "Monthly Channel (Targeted)") {
  if(version_in_range(version:officeVer, test_version:"16.0.18730.0", test_version2:"16.0.18730.20259")) {
    fix = "Version 2504 (Build 18730.20260)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18827.0", test_version2:"16.0.18827.20229")) {
    fix = "Version 2505 (Build 18827.20230)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18925.0", test_version2:"16.0.18925.20215")) {
    fix = "Version 2506 (Build 18925.20216)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
