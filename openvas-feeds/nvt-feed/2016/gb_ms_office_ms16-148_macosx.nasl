# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809759");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2016-7263", "CVE-2016-7264", "CVE-2016-7268", "CVE-2016-7266",
                "CVE-2016-7257", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7276",
                "CVE-2016-7298");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-12-14 13:38:09 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Vulnerabilities (3204068) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-148");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Office software fails to properly handle objects in memory.

  - Microsoft Office software reads out of bound memory.

  - Microsoft Office improperly checks registry settings when an attempt is
    made to run embedded content.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information and run arbitrary
  code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2011 on Mac OS X

  - Microsoft Office 2016 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3198808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94662");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94672");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94720");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3198800");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms16-148");

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

if(offVer !~ "^1[45]\."){
  exit(0);
}

if(offVer =~ "^14\." && version_is_less(version:offVer, test_version:"14.7.1"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.1.0 - 14.7.0' + '\n' ;
  security_message(data:report);
  exit(0);
}

##https://support.microsoft.com/en-us/kb/3198800
## No Information regarding office 2016
## Need to update once info is available
