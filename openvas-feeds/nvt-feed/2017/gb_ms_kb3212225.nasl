# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811812");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8567", "CVE-2017-8631", "CVE-2017-8632", "CVE-2017-8676");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 15:46:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 08:47:40 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Mac 2011 Multiple Vulnerabilities (KB3212225)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3212225");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist if:

  - Microsoft Office software fails to properly handle objects in memory.

  - The Windows Graphics Device Interface (GDI) improperly handles objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to run arbitrary code in the context of the current user,
  perform actions in the security context of the current user and retrieve
  information from a targeted system.");

  script_tag(name:"affected", value:"- Microsoft Excel for Mac 2011

  - Microsoft Office for Mac 2011");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3212225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100734");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
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

if(offVer =~ "^(14\.)")
{
  if(version_is_less(version:offVer, test_version:"14.1.7"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.1.6' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
