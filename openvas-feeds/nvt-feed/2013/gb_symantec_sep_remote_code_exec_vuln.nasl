# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803094");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2012-4348");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-01-08 10:42:29 +0530 (Tue, 08 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_name("Symantec Endpoint Protection Management Console RCE Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51527");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56846");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80601");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121210_00");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec_or_Norton/Products/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to execute
  arbitrary code via unspecified vectors.");
  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP) versions 11.0 before RU7-MP3 and 12.1 before RU2
  Symantec Endpoint Protection Small Business Edition version 12.x before 12.1 RU2");
  script_tag(name:"insight", value:"The decomposer engine in Symantec Products fails to properly validate input
  for PHP scripts.");
  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection (SEP) version 11.0 RU7-MP3 or SEP12.1 RU2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Symantec Endpoint Protection is prone to a remote code execution (RCE) vulnerability.");
  exit(0);
}


include("version_func.inc");

sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## 11.x before RU7-MP3 (11.0.7300.1294) and 12.1 before RU2 (12.1.2015.2015)
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"11.0", test_version2:"11.0.7300.1293")||
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.2015.2014"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}

if("sepsb" >< sepType  && sepVer =~ "^12" &&
   version_is_less(version:sepVer, test_version:"12.1.2015.2015"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}
