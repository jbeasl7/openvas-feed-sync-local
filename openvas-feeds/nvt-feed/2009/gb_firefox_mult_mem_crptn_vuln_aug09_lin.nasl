# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800856");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2654");
  script_name("Mozilla Firefox Multiple Memory Corruption Vulnerabilities (Aug 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36001/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35927");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code,
  phishing attack, and can cause Denial of Service.");

  script_tag(name:"affected", value:"Firefox version before 3.0.13 or 3.5 before 3.5.2 on Linux.");

  script_tag(name:"insight", value:"Multiple memory corruption due to:

  - Error in 'js_watch_set()' function in js/src/jsdbgapi.cpp in the JavaScript
    engine which can be exploited via a crafted '.js' file.

  - Error in 'libvorbis()' which is used in the application can be exploited
    via a crafted '.ogg' file.

  - Error in 'TraceRecorder::snapshot()' function in js/src/jstracer.cpp and
    other unspecified vectors.

  - Error in 'window.open()' which fails to sanitise the invalid character in
    the crafted URL. This allows remote attackers to spoof the address bar,
    and possibly conduct phishing attacks, via a crafted web page that calls
    window.open with an invalid character in the URL, makes document.write
    calls to the resulting object, and then calls the stop method during the
    loading of the error page.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.13/3.5.2.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple Memory Corruption vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.0.13")||
   version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.1")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
