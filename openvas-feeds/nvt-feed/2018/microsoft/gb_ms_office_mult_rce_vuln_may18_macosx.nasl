# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813379");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-8147", "CVE-2018-8162", "CVE-2018-8176");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-05 18:40:00 +0000 (Tue, 05 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-05-25 14:22:04 +0530 (Fri, 25 May 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (May 2018) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OS X according to Microsoft security
  update May 2018");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Microsoft PowerPoint software fails to properly validate XML content.

  - Microsoft Excel software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code in the context of the current user. If the current user
  is logged on with administrative user rights, an attacker could take control
  of the affected system.  An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Office 2016 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Microsoft Office 2016 version
  16.13.0 (Build 18051301) or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.office.com/en-gb/article/release-notes-for-office-2016-for-mac-ed2da564-6d53-4542-9954-7e3209681a41?ui=en-US&rs=en-GB&ad=GB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^((15|16)\.)" && version_is_less(version:offVer, test_version:"16.13"))
{
  report = report_fixed_ver(installed_version:offVer, fixed_version:"16.13.0");
  security_message(data:report);
  exit(0);
}
exit(0);
