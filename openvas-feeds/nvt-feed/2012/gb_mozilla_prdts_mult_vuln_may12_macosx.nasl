# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802841");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470",
                "CVE-2012-0471", "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478",
                "CVE-2012-0479");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-02 10:49:17 +0530 (Wed, 02 May 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities (May 2012) - Mac OS X");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48972/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53229");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48932/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026971");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-20.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-22.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-23.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-30.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.9
  Thunderbird version 5.0 through 11.0
  Mozilla Firefox version 4.x through 11.0
  Thunderbird ESR version 10.x before 10.0.4
  Mozilla Firefox ESR version 10.x before 10.0.4");
  script_tag(name:"insight", value:"The flaws are due to

  - Multiple unspecified vulnerabilities in the browser engine.

  - A use after free error exists within the XPConnect hashtable, when
    handling IDBKeyRange indexedDB.

  - An error within the gfxImageSurface class, when handling certain graphic
    values.

  - An error when handling multi octet encoding.

  - An error within the 'cairo_dwrite_font_face()', when rendering fonts.

  - An error within the docshell implementation, when loading pages.

  - An error when decoding ISO-2022-KR and ISO-2022-CN.

  - An error exists within the 'texImage2D()' function within WebGL, when
    using JSVAL_TO_OBJECT.

  - An error when handling RSS and Atom XML content loaded over HTTPS.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 12.0 or ESR version 10.0.4 or later, upgrade to SeaMonkey version to 2.9 or later,
  upgrade to Thunderbird version to 12.0 or ESR 10.0.4 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"10.0.3")||
     version_is_equal(version:vers, test_version:"11.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"10.0.3")||
     version_is_equal(version:vers, test_version:"11.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
