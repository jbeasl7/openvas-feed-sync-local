# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801768");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1525");
  script_name("RealNetworks RealPlayer IVR File Processing Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46946");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66209");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025245");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
arbitrary code in the context of the vulnerable application. Failed exploit
attempts will result in a denial-of-service condition.");
  script_tag(name:"affected", value:"RealPlayer versions 14.0.2.633 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper bounds checking by the
'rvrender.dll' when processing Internet Video Recording (IVR) files.");
  script_tag(name:"solution", value:"Upgrade to version 14.0.3 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

if(version_is_less_equal(version:rpVer, test_version:"12.0.1.633")){
  report = report_fixed_ver(installed_version:rpVer, vulnerable_range:"Less than or equal to 12.0.1.633");
  security_message(port: 0, data: report);
}
