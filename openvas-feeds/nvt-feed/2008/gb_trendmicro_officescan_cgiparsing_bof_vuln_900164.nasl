# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900164");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-29 14:53:11 +0100 (Wed, 29 Oct 2008)");
  script_cve_id("CVE-2008-3862");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_name("Trend Micro OfficeScan CGI Parsing Buffer Overflow Vulnerability");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/32005/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31859");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2008/Oct/0169.html");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_CriticalPatch_B1374_readme.txt");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_sp1p1_CriticalPatch_B3110_readme.txt");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3110.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_7.3_Win_EN_CriticalPatch_B1374.exe");

  script_tag(name:"impact", value:"Allows an attacker to execute arbitrary code, which may facilitate a complete
  compromise of vulnerable system.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan Corporate Edition 7.3 Build prior to 1374.

  Trend Micro OfficeScan Corporate Edition 8.0 Build prior to 3110.");

  script_tag(name:"solution", value:"Apply the referenced updates.");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to stack based buffer overflow vulnerability. The vulnerability is due to boundary error in the CGI modules when processing specially crafted HTTP request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\TrendMicro\NSC\PFW";
scanPath = registry_get_sz(key:key, item:"InstallPath");
if(!scanPath)
  exit(0);

scanPath += "PccNTMon.exe";

fileVer = GetVersionFromFile(file:scanPath);

if(fileVer && egrep(pattern:"^(8\.0(\.0(\.[0-2]?[0-9]?[0-9]?[0-9]|\.30[0-9][0-9]|\.310[0-9])?)?)$", string:fileVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
