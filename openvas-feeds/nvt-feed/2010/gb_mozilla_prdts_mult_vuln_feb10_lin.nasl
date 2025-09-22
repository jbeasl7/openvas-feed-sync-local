# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902125");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1571", "CVE-2010-0159");
  script_name("Mozilla Products Multiple Vulnerabilities (MFSA2010-03) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38287");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-45/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0405");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-03.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to potentially execute arbitrary
  code or compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Seamonkey version prior to 2.0.3

  Mozilla Thunderbird version prior to 3.0.2

  Mozilla Firefox version 3.0.x before 3.0.18 and 3.5.x before 3.5.8.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An error exists when handling 'out-of-memory conditions', can be exploited
  to trigger a memory corruption and execute arbitrary code via a specially crafted web page.

  - Multiple errors in 'nsBlockFrame::StealFrame()' function in 'layout/generic/nsBlockFrame.cpp', can be exploited to
  corrupt memory and potentially execute arbitrary code.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 3.0.18 or 3.5.8 or later

  Update to Mozilla Seamonkey version 2.0.3 or later

  Update to Mozilla Thunderbird version 3.0.2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.7") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.17"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer)
{
  if(version_is_less_equal(version:tbVer, test_version:"3.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
