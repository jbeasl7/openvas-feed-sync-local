# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815093");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-1035", "CVE-2019-1034");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2019-06-12 10:31:18 +0530 (Wed, 12 Jun 2019)");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:08:00 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (Jun 2019) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016/2019 on Mac OS X according to Microsoft security
  update June 2019");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to microsoft word software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute use a specially crafted file to perform actions in the security
  context of the current user leading to remote code execution.");

  script_tag(name:"affected", value:"- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to latest version provided by vendor.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1034");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^1[5|6]\.")
{
  if(version_is_less_equal(version:offVer, test_version:"16.16.10")){
    fix = "Upgrade to latest version provided by vendor";
  }
  else if(version_in_range(version:offVer, test_version:"16.17.0", test_version2:"16.25")){
    fix = "Upgrade to latest version provided by vendor";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:offVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
exit(99);
