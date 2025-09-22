# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902605");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-1908");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Reader Freetype Engine Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68145");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48359");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/msvr11-005.mspx");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/products/reader/security_bulletins.php#freetype");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker execute arbitrary code or crash an
  affected application or gain the same user rights as the logged-on user.");
  script_tag(name:"affected", value:"Foxit Reader version prior to 4.0.0.0619");
  script_tag(name:"insight", value:"The flaw is due to an error in FreeType engine when handling certain
  invalid font type, which allows attackers to execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 4.0.0.0619 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Foxit Reader is prone to an integer overflow vulnerability.");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/downloads/");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

foxVer = get_kb_item("foxit/reader/ver");
if(!foxVer){
  exit(0);
}

## To check Foxit Reader version before 4.0.0.0619
if(version_is_less(version:foxVer,test_version:"4.0.0.0619")){
  report = report_fixed_ver(installed_version:foxVer, fixed_version:"4.0.0.0619");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
