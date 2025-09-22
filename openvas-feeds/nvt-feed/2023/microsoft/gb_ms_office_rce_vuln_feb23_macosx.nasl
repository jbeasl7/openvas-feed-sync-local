# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821372");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2023-21716");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 23:37:00 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 12:49:57 +0530 (Wed, 15 Feb 2023)");
  script_name("Microsoft Office Outlook 2019 RCE Vulnerability (Feb 2023) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office Outlook 2019 on Mac OS X according to Microsoft
  security update February 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an unspecified error
  in Microsoft Office Word and Graphics");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute the code");

  script_tag(name:"affected", value:"Microsoft Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 16.70 (Build 23021201)
  for Microsoft Office 2019. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}
include("version_func.inc");

if(!vers = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(vers =~ "^16\.")
{
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.69")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.70 (Build 23021201)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
