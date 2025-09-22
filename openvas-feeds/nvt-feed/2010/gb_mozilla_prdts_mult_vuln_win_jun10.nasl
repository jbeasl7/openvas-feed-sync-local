# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902204");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-07-01 15:58:11 +0200 (Thu, 01 Jul 2010)");
  script_cve_id("CVE-2010-1196", "CVE-2010-1200", "CVE-2010-1199", "CVE-2010-1202");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (Jun 2010) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-29.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41050");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-30.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.5,

  Thunderbird version proior to 3.0.5 and

  Firefox version 3.5.x before 3.5.10 and 3.6.x before 3.6.4");

  script_tag(name:"insight", value:"The flaws are due to:

  - Integer overflow in the 'nsGenericDOMDataNode::SetTextInternal' function,
  which allows remote attackers to execute arbitrary code via a DOM node
  with a long text value.

  - Multiple unspecified vulnerabilities in the browser engine, which allows
  attackers to cause a denial of service or execute arbitrary code via
  unknown vectors.

  - Integer overflow in the 'XSLT' node sorting implementation, which allows
  attackers to execute arbitrary code via a large text value for a node.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.10 or 3.6.4,

  Upgrade to Seamonkey version 2.0.5,

  Upgrade to Thunderbird version 3.0.5.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.5.0", test_version2:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.3"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"2.0.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  if(version_is_less(version:tbVer, test_version:"3.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
