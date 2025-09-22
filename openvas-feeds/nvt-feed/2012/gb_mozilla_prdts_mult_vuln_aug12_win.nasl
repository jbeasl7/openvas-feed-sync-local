# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803011");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-3959", "CVE-2012-3958", "CVE-2012-3957", "CVE-2012-3972",
                "CVE-2012-3956", "CVE-2012-3971", "CVE-2012-1976", "CVE-2012-3970",
                "CVE-2012-1975", "CVE-2012-3969", "CVE-2012-1974", "CVE-2012-3968",
                "CVE-2012-1973", "CVE-2012-3967", "CVE-2012-3966", "CVE-2012-1970",
                "CVE-2012-3964", "CVE-2012-3963", "CVE-2012-3962", "CVE-2012-3978");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-30 12:20:04 +0530 (Thu, 30 Aug 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities (Aug 2012) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55249");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027450");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027451");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-57.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-58.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-62.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-63.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-64.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-70.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.12 on Windows

  Thunderbird version before 15.0 on Windows

  Mozilla Firefox version before 15.0 on Windows

  Thunderbird ESR version 10.x before 10.0.7 on Windows

  Mozilla Firefox ESR version 10.x before 10.0.7 on Windows");
  script_tag(name:"insight", value:"- Use-after-free error exists within the functions
   'nsRangeUpdater::SelAdjDeleteNode', 'nsHTMLEditRules::DeleteNonTableElements',
   'MediaStreamGraphThreadRunnable::Run', 'nsTArray_base::Length',
   'nsHTMLSelectElement::SubmitNamesValues', 'PresShell::CompleteMove',
   'gfxTextRun::GetUserData' and 'gfxTextRun::CanBreakLineBefore'.

  - Multiple unspecified errors within functions 'nsBlockFrame::MarkLineDirty'
    and the browser engine can be exploited to
    corrupt memory.

  - Errors in 'Silf::readClassMap' and 'Pass::readPass' functions within
    Graphite 2 library.

  - Use-after-free error exists within the WebGL implementation.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 15.0 or ESR version 10.0.7 or later, upgrade to SeaMonkey version to 2.12 or later
  upgrade to Thunderbird version to 15.0 or ESR 10.0.7 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"10.0.7")||
     version_in_range(version:vers, test_version:"11.0", test_version2:"14.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.12"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"10.0.7")||
     version_in_range(version:vers, test_version:"11.0", test_version2:"14.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
