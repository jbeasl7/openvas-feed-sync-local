# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802889");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-1948", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953",
                "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958",
                "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963",
                "CVE-2012-1967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-23 17:31:44 +0530 (Mon, 23 Jul 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities (Jul 2012) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54586");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027256");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027257");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-42.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-45.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-48.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-56.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.11

  Thunderbird version 5.0 through 13.0

  Mozilla Firefox version 4.x through 13.0

  Thunderbird ESR version 10.x before 10.0.6

  Mozilla Firefox ESR version 10.x before 10.0.6 on Windows");
  script_tag(name:"insight", value:"- Use-after-free error exists within the functions
   'nsGlobalWindow::PageHidden()', 'nsSMILTimeValueSpec::IsEventBased',
   'nsDocument::AdoptNode' and 'JSDependentString::undepend'.

  - Multiple unspecified errors within the browser engine can be exploited to
    corrupt memory.

  - An error within the feed-view functionality.

  - An out-of-bounds read error within the
   'ElementAnimations::EnsureStyleRuleFor()'.

  - A bad cast error within the 'nsTableFrame::InsertFrames()', can be
    exploited to corrupt memory.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later, upgrade to SeaMonkey version to 2.11 or later,
  upgrade to Thunderbird version to 14.0 or ESR 10.0.6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"10.0.5")||
     version_in_range(version:vers, test_version:"11.0", test_version2:"13.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"10.0.5")||
     version_in_range(version:vers, test_version:"11.0", test_version2:"13.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
