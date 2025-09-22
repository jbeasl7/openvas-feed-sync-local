# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810715");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2017-0030", "CVE-2017-0031", "CVE-2017-0105", "CVE-2017-0027",
                "CVE-2017-0020", "CVE-2017-0029");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 16:01:05 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (4013241) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - office software fails to properly handle objects in memory.

  - Microsoft Office software reads out of bound memory due to an uninitialized
  variable.

  - Microsoft Office improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, conduct a denial
  of service attack, and run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2011 on Mac OS X

  - Microsoft Office 2016 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3198809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96045");
  script_xref(name:"URL", value:"https://go.microsoft.com/fwlink/p/?linkid=831049");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-014");
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

if(offVer !~ "^1[45]\."){
  exit(0);
}

if(offVer =~ "^14\." && version_is_less(version:offVer, test_version:"14.7.2"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.1.0 - 14.7.1 ' + '\n' ;
  security_message(data:report);
}

if(offVer =~ "^15\." && version_is_less(version:offVer, test_version:"15.32.0"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 15.0 - 15.31.0 ' + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
