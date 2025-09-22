# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805475");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0836", "CVE-2015-0835", "CVE-2015-0834", "CVE-2015-0833",
                "CVE-2015-0832", "CVE-2015-0831", "CVE-2015-0830", "CVE-2015-0829",
                "CVE-2015-0828", "CVE-2015-0827", "CVE-2015-0826", "CVE-2015-0825",
                "CVE-2015-0824", "CVE-2015-0823", "CVE-2015-0822", "CVE-2015-0821",
                "CVE-2015-0820", "CVE-2015-0819");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-03 14:30:16 +0530 (Tue, 03 Mar 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 (Mar 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Some unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - WebRTC implementation accepting turns: and stuns: URIs despite the program
  itself not supporting TLS connections to TURN and STUN servers.

  - Multiple untrusted search path vulnerabilities in updater.exe.

  - Improper recognition of the equivalence of domain names with and without a
  trailing . (dot) character.

  - Use-after-free error in the 'IDBDatabase::CreateObjectStore' function in
  dom/indexedDB/IDBDatabase.cpp script.

  - Flaw in the 'WebGLContext::CompileShader' function in
  dom/canvas/WebGLContextGL.cpp script that is triggered when handling specially
  crafted WebGL content that writes strings.

  - Buffer overflow in libstagefright.

  - Double free vulnerability in the 'nsXMLHttpRequest::GetResponse' function.

  - Heap-based buffer overflow in the 'mozilla::gfx::CopyRect' and
  'nsTransformedTextRun::SetCapitalization' functions.

  - Stack-based buffer underflow in the 'mozilla::MP3FrameParser::ParseBuffer'
  function

  - Out-of-bounds Memory Zeroing Issue in Cairo graphics library implementation

  - Flaw in web content that relies on the Caja Compiler and other similar
  sandboxing libraries for protection.

  - Manual Link Opening Context Restriction Bypass flaw in Firefox.

  - Flaw in the autocomplete feature for forms.

  - Multiple use-after-free vulnerabilities in OpenType Sanitiser.

  - Heap use-after-free flaw in the 'ots::ots_gasp_parse' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, bypass certain security
  restrictions, cause a denial of service, man-in the-middle attack, execute
  arbitrary code, conduct spoofing and clickjacking attacks and local privilege
  escalation.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 36.0 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 36.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72743");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72745");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72757");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72759");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-26");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"36.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     36.0\n';
  security_message(data:report);
  exit(0);
}
