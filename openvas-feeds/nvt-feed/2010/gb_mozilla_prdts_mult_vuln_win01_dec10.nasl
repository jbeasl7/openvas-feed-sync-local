# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801498");
  script_version("2024-02-12T14:37:47+0000");
  script_tag(name:"last_modification", value:"2024-02-12 14:37:47 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3770", "CVE-2010-3771",
                "CVE-2010-3773", "CVE-2010-3772", "CVE-2010-3774", "CVE-2010-3775");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (MFSA2010-76, MFSA2010-80, MFSA2010-81, MFSA2010-84) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-80.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-81.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-84.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-76.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version before 2.0.11

  Firefox version before 3.5.16 and 3.6.x before 3.6.13");

  script_tag(name:"insight", value:"The flaws are due to:

  - Use-after-free vulnerability.

  - Integer overflow in the NewIdArray function.

  - Cross-site Scripting (XSS) vulnerabilities in the rendering engine allows
  remote attackers to inject arbitrary web script.

  - Not properly handle injection of an 'ISINDEX' element into an
  about:blank page.

  - Error in 'XMLHttpRequestSpy' module in the 'Firebug' add-on is used,
  does not properly handle interaction between the 'XMLHttpRequestSpy' object
  and chrome privileged objects.

  - Not properly calculate index values for certain child content in a 'XUL' tree.

  - Error in 'NS_SecurityCompareURIs' function in netwerk/base/public/nsNetUtil.h
  which does not properly handle 'about:neterror' and 'about:certerror' pages.

  - Not properly handle certain redirections involving 'data: URLs' and
  'Java LiveConnect' scripts, which allows remote attackers to start processes.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey are prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.16 or 3.6.13 or later

  Upgrade to Seamonkey version 2.0.11 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.13") ||
     version_is_less(version:ffVer, test_version:"3.5.16"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
