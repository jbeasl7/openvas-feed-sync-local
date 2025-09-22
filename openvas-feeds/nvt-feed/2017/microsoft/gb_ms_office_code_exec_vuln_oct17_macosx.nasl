# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811869");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-11825");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 14:03:00 +0000 (Fri, 16 Mar 2018)");
  script_tag(name:"creation_date", value:"2017-10-17 11:19:59 +0530 (Tue, 17 Oct 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerability (Oct 2017) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OS X according to Microsoft security
  update October 2017");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Office fails
  to properly handle objects in memory. An attacker who successfully exploited
  the vulnerability could use a specially crafted file to perform actions in
  the security context of the current user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user. Failed exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"Microsoft Office 2016 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101124");
  script_xref(name:"URL", value:"https://support.office.com/en-gb/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.39"))
{
  report = report_fixed_ver(installed_version:offVer, fixed_version:"15.39.0 (Build 17101000)");
  security_message(data:report);
  exit(0);
}
exit(0);
