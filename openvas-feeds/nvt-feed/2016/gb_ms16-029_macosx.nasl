# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807892");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2016-0134");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-05 14:26:23 +0530 (Wed, 05 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerability (3141806) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-029");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as Office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2011 on Mac OS X

  - Microsoft Office 2016 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3138328");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3138327");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-029");

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

if((offVer =~ "^(14\.)") || (offVer =~ "^(15\.)"))
{

  if(offVer =~ "^(14\.)" && version_is_less(version:offVer, test_version:"14.6.2"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.6.1' + '\n' ;
    security_message(data:report);
  }

  if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.20.0"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 15.0 - 15.19 ' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);

