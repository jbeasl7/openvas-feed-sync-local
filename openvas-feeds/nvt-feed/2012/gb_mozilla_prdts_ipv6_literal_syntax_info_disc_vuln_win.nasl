# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802579");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-3670");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-03 17:51:59 +0530 (Fri, 03 Feb 2012)");
  script_name("Mozilla Products IPv6 Literal Syntax Cross Domain Information Disclosure Vulnerability - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47839/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51786");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026613");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to get sensitive information.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.4
  Thunderbird version before 3.1.18 and 5.0 through 6.0
  Mozilla Firefox version before 3.6.26 and 4.x through 6.0");
  script_tag(name:"insight", value:"The flaw is due to requests made using IPv6 syntax using XMLHttpRequest
  objects through a proxy may generate errors depending on proxy configuration
  for IPv6. The resulting error messages from the proxy may disclose sensitive
  data.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to an information disclosure vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.27 or 7.0 or later.

  Upgrade to SeaMonkey version to 2.4 or later.

  Upgrade to Thunderbird version to 3.1.18 or 7.0 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!isnull(ffVer))
{
  if(version_is_less(version:ffVer, test_version:"3.6.26") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"6.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!isnull(tbVer))
{
  if(version_is_less(version:tbVer, test_version:"3.1.18") ||
     version_in_range(version:tbVer, test_version:"5.0", test_version2:"6.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
