# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802804");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0757",
                "CVE-2012-0756", "CVE-2012-0767");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 16:05:58 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-02-22 14:34:05 +0530 (Wed, 22 Feb 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Feb 2012) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52040");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026694");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48033");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-03.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application or cause a denial of service condition.");

  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.15
  Adobe Flash Player version 11.x through 11.1.102.55 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to:

  - A memory corruption error in ActiveX control

  - A type confusion memory corruption error

  - An unspecified error related to MP4 parsing

  - Many unspecified errors which allows to bypass certain security
  restrictions

  - Improper validation of user supplied input which allows attackers to
  execute arbitrary HTML and script code in a user's browser session.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.15 or 11.1.102.62 or later.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(isnull(flashVer)){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

if(version_is_less(version:flashVer, test_version:"10.3.183.15")||
   version_in_range(version:flashVer, test_version:"11.0", test_version2:"11.1.102.55")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
