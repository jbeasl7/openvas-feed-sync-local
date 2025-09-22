# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811506");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8501");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-14 10:32:00 +0000 (Fri, 14 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-12 08:54:59 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Office Remote Code Execution Vulnerability - Mac OS X (KB3212224)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3212224");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when the Microsoft Office
  software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office for Mac 2011

  - Microsoft Office 2016 for Mac");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3212224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99441");
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

if(offVer =~ "^(14\.)" && version_in_range(version:offVer, test_version:"14.1.0", test_version2:"14.7.5"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.1.0 - 14.7.5' + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.36.0"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 15.0 - 15.35.0' + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
