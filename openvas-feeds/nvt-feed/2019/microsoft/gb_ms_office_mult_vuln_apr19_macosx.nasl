# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815035");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-0822", "CVE-2019-0828");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2019-04-10 09:14:49 +0530 (Wed, 10 Apr 2019)");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Vulnerabilities (Apr 2019) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016/2019 on Mac OS X according to Microsoft security
  update April 2019");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Microsoft Excel software fails to properly handle objects in memory.

  - Microsoft Graphics Components improperly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on a target system. If the current user is logged on
  with administrative user rights, an attacker could take control of the affected
  system.");

  script_tag(name:"affected", value:"- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Microsoft Office 2016 16.16.9 or
  Microsoft Office 2019 16.24 or later on Mac OS X. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac");

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

if(offVer =~ "^1[56]\.")
{
  if(version_is_less_equal(version:offVer, test_version:"16.16.8")||
     version_in_range(version:offVer, test_version:"16.17.0", test_version2:"16.23.1"))
  {
    report = report_fixed_ver(installed_version:offVer, fixed_version:"Microsoft Office 2016 16.16.9 or Microsoft Office 2019 16.24 or later.");
    security_message(data:report);
    exit(0);
  }
}
exit(99);
