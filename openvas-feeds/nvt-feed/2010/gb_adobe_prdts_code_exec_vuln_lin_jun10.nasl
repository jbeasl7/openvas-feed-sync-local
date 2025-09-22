# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801361");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-1297");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:20:44 +0000 (Fri, 28 Jun 2024)");
  script_name("Adobe Products Remote Code Execution Vulnerability (Jun 2010) - Linux");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40586");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1348");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa10-01.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl", "gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code by tricking a user into opening a specially crafted PDF file.");

  script_tag(name:"affected", value:"Adobe Reader version 9.x to 9.3.2

  Adobe Flash Player version 9.0.x to 9.0.262 and 10.x through 10.0.45.2");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption error in the
  'libauthplay.so.0.0.0' library and 'SWF' file when processing ActionScript
  Virtual Machine 2 (AVM2) 'newfunction' instructions within Flash content in a PDF document.");

  script_tag(name:"summary", value:"Adobe products is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to Adobe Flash Player 10.1.53.64 or 9.0.277.0 or later

  For Adobe Reader a patch was released by the Vendor, please see the references for more information.");

  exit(0);
}

include("version_func.inc");

pVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(pVer)
{
  #  Adobe Flash Player version 9.0.0 to 9.0.262 and 10.x to 10.0.45.2
  if(version_in_range(version:pVer, test_version:"9.0.0", test_version2:"9.0.262") ||
  version_in_range(version:pVer, test_version:"10.0", test_version2:"10.0.45.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Adobe Reader
arVer = get_kb_item("Adobe/Reader/Linux/Version");
if(arVer)
{
  if(version_in_range(version:arVer, test_version:"9.0", test_version2:"9.3.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
