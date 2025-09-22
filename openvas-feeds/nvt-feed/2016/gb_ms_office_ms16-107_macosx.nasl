# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807367");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2016-0141", "CVE-2016-3357");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-09-14 14:45:19 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (3185852) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3186807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92786");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3186805");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer && offVer =~ "^(14\.)")
{
  if(version_is_less(version:offVer, test_version:"14.6.7"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.6.7 ' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.25.0"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 15.0 - 15.25.0 ' + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
