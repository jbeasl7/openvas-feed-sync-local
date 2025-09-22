# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800641");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835",
                "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1840", "CVE-2009-1841",
                "CVE-2009-1392");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities (Jun 2009) - Linux");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35326");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary JavaScript code
  execution, spoofing attacks, sensitive information disclosure, and can cause
  denial of service.");
  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.17 on Linux.");
  script_tag(name:"insight", value:"- Error in js/src/xpconnect/src/xpcwrappedjsclass.cpp file will allow attacker
    to execute arbitrary web script.

  - Multiple errors in the layout and JavaScript engines that can corrupt memory

  - Error in location bar, when used as part of an IDN.due to certain invalid
    unicode characters being displayed as whitespace.

  - An error when handling a non-200 response returned by a proxy in reply to a
    CONNECT request, which could cause the body of the response to be rendered
    within the context of the request 'Host:' header.

  - An error when handling event listeners attached to an element whose owner
    document is null.

  - Due to the 'file:' resource inheriting the principal of the previously
    loaded document when loaded via the location, allow unauthorized access to
    local files.

  - Due to content-loading policies not being checked before loading external
    script files into XUL documents, which could be exploited to bypass
    restrictions.

  - Error exists via vectors involving 'double frame construction.'

  - Error exists in JavaScript engine is caused via vectors related to
    js_LeaveSharpObject, ParseXMLSource, and a certain assertion in jsinterp.c.");
  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.17.");
  script_tag(name:"summary", value:"Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

seamonkeyVer = get_kb_item("Seamonkey/Linux/Ver");
if(!seamonkeyVer)
  exit(0);

if(version_is_less(version:seamonkeyVer ,test_version:"1.1.17")){
  report = report_fixed_ver(installed_version:seamonkeyVer, fixed_version:"1.1.17");
  security_message(port: 0, data: report);
}
