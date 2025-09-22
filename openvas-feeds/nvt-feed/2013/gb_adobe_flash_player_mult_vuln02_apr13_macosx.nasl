# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803384");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-1380", "CVE-2013-1379", "CVE-2013-1378", "CVE-2013-2555");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-04-19 11:16:07 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -02 (Apr 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58947");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58951");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-11.html");
  script_xref(name:"URL", value:"http://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.68 and earlier, and 11.x to 11.6.602.180 on
  Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error when initializing certain pointer arrays.

  - Integer overflow error.");
  script_tag(name:"solution", value:"Upgrade to version 10.3.183.75 or 11.7.700.169.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"10.3.183.68") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.6.602.180"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
