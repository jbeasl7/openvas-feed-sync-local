# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803202");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-0761", "CVE-2013-0763", "CVE-2013-0771", "CVE-2013-0749");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-16 16:20:06 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities-03 (Jan 2013) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51752/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57197");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57205");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial
  of service or execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"- SeaMonkey version before 2.15

  - Thunderbird version before 17.0.2

  - Mozilla Firefox version before 18.0

  - Thunderbird ESR version 17.x before 17.0.1

  - Mozilla Firefox ESR version 17.x before 17.0.1");

  script_tag(name:"insight", value:"- Use-after-free errors exist within the
  'mozilla::TrackUnionStream::EndTrack' implementation and Mesa when resizing a WebGL canvas.

  - Unspecified error in the browser engine can be exploited to corrupt memory.

  - An error within the 'gfxTextRun::ShrinkToLigatureBoundaries()' function.");

  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 18.0 or ESR version 17.0.1
  or later, update to SeaMonkey version to 2.15 or later, update to Thunderbird version to 17.0.2
  or ESR version 17.0.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
esrvers = get_kb_item("Firefox-ESR/Win/Ver");
if(vers || esrvers) {
  if((vers && version_is_less(version:vers, test_version:"18.0")) ||
     (esrvers && version_is_equal(version:esrvers, test_version:"17.0.0"))) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers && version_is_less(version:vers, test_version:"2.15")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

vers = get_kb_item("Thunderbird/Win/Ver");
esrvers = get_kb_item("Thunderbird-ESR/Win/Ver");
if(vers || esrvers) {
  if((vers && version_is_less(version:vers, test_version:"17.0.2")) ||
     (esrvers && version_is_equal(version:esrvers, test_version:"17.0.0"))) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);