# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900220");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-2437");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_family("Buffer overflow");
  script_name("Trend Micro OfficeScan Server cgiRecvFile.exe Buffer Overflow Vulnerability.");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31342/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31139");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020860.html");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln31139.html");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_Win_EN_CriticalPatch_B1361.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2424.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3060.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_7.3_Win_EN_CriticalPatch_B1367.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/CSM_3.6_OSCE_7.6_Win_EN_CriticalPatch_B1195.exe");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to a buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in cgiRecvFile.exe can be exploited
  to cause a stack based buffer overflow by sending a specially crafted
  HTTP request with a long ComputerName parameter.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan Corporate Edition version 8.0

  Trend Micro OfficeScan Corporate Edition versions 7.0 and 7.3

  Trend Micro Client Server Messaging Security (CSM) for SMB versions 2.x and 3.x");

  script_tag(name:"solution", value:"Partially Fixed.

  Fix is available for Trend Micro OfficeScan 8.0, 7.3 and Client Server Messaging Security (CSM) 3.6.
  Please see the references for more information.");

  script_tag(name:"impact", value:"Remote exploitation could allow execution of arbitrary code to
  cause complete compromise of system and failed attempt leads to denial of service condition.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

scanVer = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service\Information", item:"Server_Version");
if(!scanVer)
  exit(0);

if(!egrep(pattern:"^([0-7]\..*|8\.0)$", string:scanVer))
  exit(0);

offPath = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service\Information", item:"Local_Path");
if(!offPath)
  exit(0);

# For Trend Micro Client Server Messaging Security and Office Scan 8 or 7.0
if(registry_key_exists(key:"SOFTWARE\TrendMicro\CSM") || scanVer =~ "^(8\..*|[0-7]\.[0-2](\..*)?)$"){
  security_message(port:0);
  exit(0);
}

fullPath = offPath + "Web\CGI\cgiRecvFile.exe";

fileVersion = GetVersionFromFile(file:fullPath);

if(!fileVersion)
  exit(0);

if(egrep(pattern:"^7\.3\.0\.(0?[0-9]?[0-9]?[0-9]|1[0-2][0-9][0-9]|13[0-5][0-9]|136[0-6])$", string:scanVer)){
  security_message(port:0);
  exit(0);
}

exit(99);
