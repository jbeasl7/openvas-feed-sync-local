# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817378");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2020-1193", "CVE-2020-1218", "CVE-2020-1224", "CVE-2020-1338",
                "CVE-2020-16855");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-31 22:16:00 +0000 (Sun, 31 Dec 2023)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name("Microsoft Office Multiple Vulnerabilities (Sep 2020) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 and Office 2019 on Mac OS X according to
  Microsoft security updates September 2020");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Microsoft Excel because it fails to properly handle objects in memory.

  - An error when Microsoft Excel improperly discloses the contents of its memory.

  - An error when Microsoft Office software reads out of bound memory due to an
    uninitialized variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and gain access to sensitive information.");

  script_tag(name:"affected", value:"Microsoft Office 2016 and Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to latest version for Microsoft
  Office 2016 and Office 2019. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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
  if(version_is_less_equal(version:offVer, test_version:"16.16.25")){
    fix = "Apply latest update";
  }
  else if(version_in_range(version:offVer, test_version:"16.17.0", test_version2:"16.40")){
    fix = "Apply latest update";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:offVer, fixed_version:fix);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
