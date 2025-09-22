# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818018");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2021-27054", "CVE-2021-27057");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-05 16:15:00 +0000 (Wed, 05 May 2021)");
  script_tag(name:"creation_date", value:"2021-03-12 19:24:13 +0530 (Fri, 12 Mar 2021)");
  script_name("Microsoft Office 2019 Multiple Vulnerabilities (Mar 2021) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OS X according to
  Microsoft security updates March 2021");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  Microsoft Office 2019 for Mac OS X");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and disclose the information.");

  script_tag(name:"affected", value:"Microsoft Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to latest version for Microsoft
  Office 2019. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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
  if(version_is_less_equal(version:offVer, test_version:"16.46")){
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
