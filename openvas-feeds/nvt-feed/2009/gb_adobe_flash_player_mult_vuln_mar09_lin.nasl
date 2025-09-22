# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800360");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0521", "CVE-2009-0522");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Mar 2009) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33890");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause remote code
  execution, compromise system privileges or may cause exposure of sensitive information.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 1.5.1

  Adobe Flash Player 9 version prior to 9.0.159.0

  Adobe Flash Player 10 version prior to 10.0.22.87");

  script_tag(name:"insight", value:"- Error while processing multiple references to an unspecified object which
  can be exploited by tricking the user to access a malicious crafted SWF file.

  - Input validation error in the processing of SWF file.

  - Error while displaying the mouse pointer on Windows which may cause 'Clickjacking' attacks.

  - Error in the Linux Flash Player binaries which can cause disclosure of sensitive information.");

  script_tag(name:"summary", value:"Adobe Products is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to version Adobe Flash Player 9.0.159.0 or 10.0.22.87.

  Update to version 1.5.1 for Adobe AIR.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.22.86")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

airVer = get_kb_item("Adobe/Air/Linux/Ver");
if(airVer =~ "^[01]\.")
{
  if(version_is_less(version:airVer, test_version:"1.5.1")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
