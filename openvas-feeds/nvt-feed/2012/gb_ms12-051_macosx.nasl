# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901210");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-1894");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-07-11 08:54:28 +0530 (Wed, 11 Jul 2012)");
  script_name("Microsoft Office Privilege Elevation Vulnerability (2721015) - Mac OS X");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54361");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2011 for Mac.");

  script_tag(name:"insight", value:"The application being installed with insecure folder permissions and can
  be exploited to create arbitrary files in certain directories.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-051.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");
if(!offVer){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.2.2")){
  report = report_fixed_ver(installed_version:offVer, vulnerable_range:"14.0 - 14.2.2");
  security_message(port:0, data:report);
}
