# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836233");
  script_version("2025-07-16T05:43:53+0000");
  script_cve_id("CVE-2025-47994", "CVE-2025-48812", "CVE-2025-49695", "CVE-2025-49696",
                "CVE-2025-49697", "CVE-2025-49698", "CVE-2025-49699", "CVE-2025-49700",
                "CVE-2025-49702", "CVE-2025-49703", "CVE-2025-49705", "CVE-2025-49711",
                "CVE-2025-49756");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 14:09:43 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-09 05:55:46 +0000 (Wed, 09 Jul 2025)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) RCE Vulnerability (Jul 2025)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Office Click-to-Run update July 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to conduct
  remote code execution, information disclosure and elevation of privilege.");

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
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.18925.20158"))
    fix = "Version 2506 (Build 18925.20158)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2502 (Build 18526.20472)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.18526.20472"))
    fix = "Version 2502 (Build 18526.20472)";
}

## Semi-Annual Enterprise Channel: Version 2502 (Build 18526.20472)
## Semi-Annual Enterprise Channel: Version 2408 (Build 17928.20604)
## Semi-Annual Enterprise Channel: Version 2402 (Build 17328.20856)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel") {
  if(version_in_range(version:officeVer, test_version:"16.0.17328.0", test_version2:"16.0.17328.20855")) {
    fix = "Version 2402 (Build 17328.20856)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.17928.0", test_version2:"16.0.17928.20603")) {
      fix = "Version 2408 (Build 17928.20604)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18526.0", test_version2:"16.0.18526.20471")) {
      fix = "Version 2502 (Build 18526.20472)";
  }
}

## Monthly Enterprise Channel: Version 2505 (Build 18827.20202)
## Monthly Enterprise Channel: Version 2504 (Build 18730.20240)
## Monthly Enterprise Channel: Version 2503 (Build 18623.20316)
else if(UpdateChannel == "Monthly Channel (Targeted)") {
  if(version_in_range(version:officeVer, test_version:"16.0.18623.0", test_version2:"16.0.18623.20315")) {
    fix = "Version 2503 (Build 18623.20316)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18730.0", test_version2:"16.0.18730.20239")) {
    fix = "Version 2504 (Build 18730.20240)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.18827.0", test_version2:"16.0.18827.20201")) {
    fix = "Version 2505 (Build 18827.20202)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
