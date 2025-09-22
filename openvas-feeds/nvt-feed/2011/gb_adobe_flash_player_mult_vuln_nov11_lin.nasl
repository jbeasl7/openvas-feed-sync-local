# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902752");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2011-2445", "CVE-2011-2450", "CVE-2011-2451", "CVE-2011-2452",
                "CVE-2011-2453", "CVE-2011-2454", "CVE-2011-2455", "CVE-2011-2456",
                "CVE-2011-2457", "CVE-2011-2458", "CVE-2011-2459", "CVE-2011-2460");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-11-16 12:10:29 +0530 (Wed, 16 Nov 2011)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Nov 2011) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via unspecified
  vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version prior to 10.3.183.11 and 11.x through 11.0.1.152 on Linux");
  script_tag(name:"insight", value:"The flaws are due to memory corruption, heap corruption, buffer
  overflow, stack overflow errors that could lead to code execution.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.11 or 11.1.102.55 or later");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46818/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50619");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50622");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50625");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50629");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-28.html");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!vers)
  exit(0);

vers = ereg_replace(pattern:",", string:vers, replace: ".");

if(version_is_less(version:vers, test_version:"10.3.183.11") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.1.152")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
