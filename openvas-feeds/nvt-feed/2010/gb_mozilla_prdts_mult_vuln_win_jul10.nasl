# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801385");
  script_version("2024-02-12T14:37:47+0000");
  script_tag(name:"last_modification", value:"2024-02-12 14:37:47 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213",
                "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754",
                "CVE-2010-0654");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:26:59 +0000 (Sat, 03 Feb 2024)");
  script_name("Mozilla Products Multiple Vulnerabilities (MFSA2010-34, MFSA2010-39, MFSA2010-40, MFSA2010-42, MFSA2010-46, MFSA2010-47) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-34.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41824");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-39.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-40.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-42.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-46.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-47.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version 2.0.x before 2.0.6

  Firefox version 3.5.x before 3.5.11 and 3.6.x before 3.6.7

  Thunderbird version 3.0.x before 3.0.6 and 3.1.x before 3.1.1");

  script_tag(name:"insight", value:"The flaws are due to:

  - A memory corruption errors in the browser engine, which allows to corrupt
  the memory under certain circumstances.

  - An integer overflow error exists when array class used to store CSS values,
  which allows to execute arbitrary codes.

  - An integer overflow error in the implementation of the XUL <tree> element's
  'selection' attribute. When the size of a new selection is sufficiently
  large the integer used in calculating the length of the selection, which
  allows attacker to call into deleted memory and run arbitrary code.

  - Error in handling of 'CSS' selector into points A and B of a target page,
  data can be read across domains by injecting bogus CSS selectors into a
  target site and then retrieving the data using JavaScript APIs.

  - Cross-origin data leakage errors occurs from script filename in error
  messages.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird are prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.11 or 3.6.7 or later

  Upgrade to Seamonkey version 2.0.6 or later

  Upgrade to Thunderbird version 3.0.6 or 3.1.1 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.6") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.10"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_in_range(version:smVer, test_version:"2.0", test_version2:"2.0.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_equal(version:tbVer, test_version:"3.1.0") ||
     version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
