# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900033");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_cve_id("CVE-2008-0120", "CVE-2008-0121", "CVE-2008-1455");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft PowerPoint Could Allow Remote Code Execution Vulnerabilities (949785)");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30552");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30579");

  script_tag(name:"summary", value:"This host is missing critical security update according to
  Microsoft Bulletin MS08-051.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - an integer overflow error when handling CString objects.

  - a memory calculation error when processing malformed picture
   indexes and list values.");

  script_tag(name:"affected", value:"- Microsoft PowerPoint 2002/XP/2003/2007

  - Microsoft PowerPoint Viewer 2003/2007");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"impact", value:"Remote attackers could be able to corrupt memory locations via
  a specially crafted PowerPoint files.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^(9|1[012])\.")
{
  pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
  if(!pptVer || pptVer !~ "^(9|1[012])\."){
    exit(0);
  }

  if(version_in_range(version:pptVer, test_version:"9.0", test_version2:"9.0.0.8968")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6841")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8226")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:pptVer, test_version:"12.0", test_version2:"12.0.6300.4999")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
