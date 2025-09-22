# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801903");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0053");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Unspecified Vulnerabilities (MFSA2011-08) - Windows");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0531");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-08.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors.");
  script_tag(name:"affected", value:"Seamonkey version before 2.0.12
  Thunderbird version before 3.1.8
  Firefox version before 3.5.17 and 3.6.x before 3.6.14");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in browser engine, when handling
  a recursive call to 'eval()' wrapped in a try or catch statement, which could
  be exploited to cause a denial of service.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird are prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.17 or 3.6.14 or later,
  Upgrade to Seamonkey version 2.0.12 or later,
  Upgrade to Thunderbird version 3.1.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");


vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.5.17") ||
     version_in_range(version:vers, test_version:"3.6.0", test_version2:"3.6.13"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"2.0.12"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.8")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
