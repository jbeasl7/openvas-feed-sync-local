# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832249");
  script_version("2024-07-18T05:05:48+0000");
  script_cve_id("CVE-2023-36896", "CVE-2023-36895", "CVE-2023-35371");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-18 05:05:48 +0000 (Thu, 18 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-08 18:33:00 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 12:47:48 +0530 (Thu, 10 Aug 2023)");
  script_name("Microsoft Office 2019 Multiple Vulnerabilities (Aug 2023) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2019 on Mac OS X according to Microsoft security
  update August 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution vulnerabilities in Microsoft Excel, Microsoft Outlook and
  Microsoft Office components.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2019 version 16.75.2 (Build 23072301) and
  prior on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 16.76 (Build 23081101) or later.");

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

if(!vers = get_kb_item("MS/Office/MacOSX/Ver"))
  exit(0);

if(vers =~ "^16\.") {
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.75.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.76 (Build 23081101)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
