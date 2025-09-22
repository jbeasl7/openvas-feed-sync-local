# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803201");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-16 16:06:20 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities-02 (Jan 2013) - Mac OS X");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51752/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57203");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.15 on Mac OS X

  Thunderbird version before 17.0.2 on Mac OS X

  Mozilla Firefox version before 18.0 on Mac OS X

  Thunderbird ESR version 10.x before 10.0.12 and 17.x before 17.0.1 on Mac OS X

  Mozilla Firefox ESR version 10.x before 10.0.12 and 17.x before 17.0.1 on Mac OS X");

  script_tag(name:"insight", value:"- Use-after-free errors exist within the functions
    'nsSVGPathElement::GetPathLengthScale' and 'imgRequest::OnStopFrame' and
    in the '~nsHTMLEditRules' implementation.

  - Unspecified error in the browser engine can be exploited to corrupt memory.");

  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 18.0 or ESR version 10.0.12 or 17.0.1 or later, upgrade to SeaMonkey version to 2.15 or later,
  upgrade to Thunderbird version to 17.0.2 or ESR 10.0.12 or 17.0.1 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
esrvers = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");
if(vers || esrvers) {
  if(version_is_less(version:vers, test_version:"18.0") ||
     version_is_equal(version:esrvers, test_version:"17.0.0") ||
     version_in_range(version:esrvers, test_version:"10.0", test_version2:"10.0.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"2.15"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
esrvers = get_kb_item("Thunderbird-ESR/MacOSX/Version");
if(vers || esrvers) {
  if(version_is_less(version:vers, test_version:"17.0.2") ||
     version_is_equal(version:esrvers, test_version:"17.0.0") ||
     version_in_range(version:esrvers, test_version:"10.0", test_version2:"10.0.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
