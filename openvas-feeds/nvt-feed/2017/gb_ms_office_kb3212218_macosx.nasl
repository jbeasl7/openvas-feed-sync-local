# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810743");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2017-0207");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-12 15:10:09 +0530 (Wed, 12 Apr 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Spoofing Vulnerability (KB3212218) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a moderate security
  update according to Microsoft security update KB3212218");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A spoofing vulnerability exists when
  Microsoft Outlook for Mac improperly validates HTML tag input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to the user's authentication information or login
  credentials.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3212218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97463");
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

if(offVer !~ "^14\."){
  exit(0);
}

if(offVer =~ "^14\." && version_is_less(version:offVer, test_version:"14.7.3"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.0 - 14.7.2 ' + '\n' ;
  security_message(data:report);
}
