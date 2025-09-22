# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902493");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-12-14 09:22:08 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Publisher Remote Code Execution Vulnerabilities (2607702)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Publisher/Version");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50955");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596705");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-091/");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code on
  the remote system.");
  script_tag(name:"affected", value:"- Microsoft Publisher 2003 Service Pack 3 and prior

  - Microsoft Publisher 2007 Service Pack 3 and prior");
  script_tag(name:"insight", value:"The flaw is due to the way Microsoft Publisher parses specially
  crafted Publisher files, which could allow attackers to execute arbitrary
  code by tricking a user into opening a specially crafted Publisher file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-091.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pubVer = get_kb_item( "SMB/Office/Publisher/Version" );
if( isnull( pubVer ) ) exit( 0 );

if( version_in_range( version:pubVer, test_version:"11.0", test_version2:"11.0.8341" ) ||
    version_in_range( version:pubVer, test_version:"12.0", test_version2:"12.0.6652.4999" ) ){
  report = report_fixed_ver( installed_version:pubVer, fixed_version:"11.0.8341/12.0.6652.4999" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
