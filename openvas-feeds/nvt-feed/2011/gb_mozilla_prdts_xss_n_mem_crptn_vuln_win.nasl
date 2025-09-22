# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802518");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3650", "CVE-2011-3648");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-14 13:23:08 +0530 (Mon, 14 Nov 2011)");
  script_name("Mozilla Products XSS and Memory Corruption Vulnerabilities - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-49.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50595");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-47.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                           "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to inject arbitrary web script
  or HTML via crafted text with Shift JIS encoding and cause a denial of
  service.");
  script_tag(name:"affected", value:"Thunderbird version prior to 3.1.16, 5.0 through 7.0
  Mozilla Firefox version prior to 3.6.24, 4.x through 7.0");
  script_tag(name:"insight", value:"The flaws are due to

  - Error, while handling invalid sequences in the Shift-JIS encoding.

  - Crash, when using Firebug to profile a JavaScript file with many functions.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird is prone to cross site scripting and memory corruption vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 8.0 or 3.6.24 or later, Upgrade to Thunderbird version to 8.0 or 3.1.16 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");


vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.24") ||
     version_in_range(version:vers, test_version:"4.0", test_version2:"7.0"))
  {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.16") ||
     version_in_range(version:vers, test_version:"4.0", test_version2:"7.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
