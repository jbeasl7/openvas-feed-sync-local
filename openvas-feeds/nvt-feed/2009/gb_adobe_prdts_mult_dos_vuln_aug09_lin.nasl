# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800854");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866",
                "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
  script_name("Adobe Flash Player/Air Multiple DoS Vulnerabilities (Aug 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35948/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35908");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2086");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code,
  gain elevated privileges, gain knowledge of certain information and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 1.5.2

  Adobe Flash Player 9 version prior to 9.0.246.0

  Adobe Flash Player 10 version prior to 10.0.32.18 on Linux.");

  script_tag(name:"insight", value:"Multiple vulnerabilities which can be to exploited to cause memory
  corruption, null pointer, privilege escalation, heap-based buffer overflow,
  local sandbox bypass, and input validation errors when processing specially crafted web pages.");

  script_tag(name:"solution", value:"Update to Adobe Air 1.5.2 or Adobe Flash Player 9.0.246.0 or 10.0.32.18.");

  script_tag(name:"summary", value:"Adobe Flash Player/Air is prone to multiple Denial of Service vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"9.0.246.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.32.17"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

airVer = get_kb_item("Adobe/Air/Linux/Ver");
if(airVer != NULL)
{
  if(version_is_less(version:airVer, test_version:"1.5.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
