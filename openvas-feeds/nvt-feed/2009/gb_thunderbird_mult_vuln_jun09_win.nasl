# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800638");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838",
                "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-1392");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities (Jun 2009) - Windows");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35326");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary JavaScript code
  execution, spoofing attacks, sensitive information disclosure, and can cause
  denial of service.");
  script_tag(name:"affected", value:"Thunderbire version prior to 2.0.0.22 on Windows.");
  script_tag(name:"insight", value:"- Error in js/src/xpconnect/src/xpcwrappedjsclass.cpp file will allow attacker
    to execute arbitrary web script.

  - An error when handling a non-200 response returned by a proxy in reply to a
    CONNECT request, which could cause the body of the response to be rendered
    within the context of the request 'Host:' header.

  - An error when handling event listeners attached to an element whose owner
    document is null.

  - Due to content-loading policies not being checked before loading external
    script files into XUL documents, which could be exploited to bypass
    restrictions.

  - An error when handling event listeners attached to an element whose owner
    document is null.

  - Error exists in JavaScript engine is caused via vectors related to
    js_LeaveSharpObject, ParseXMLSource, and a certain assertion in jsinterp.c.

  - Error exists via vectors involving 'double frame construction.'");
  script_tag(name:"solution", value:"Upgrade to Firefox version 2.0.0.22.");
  script_tag(name:"summary", value:"Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

thunderbirdVer = get_kb_item("Thunderbird/Win/Ver");
if(!thunderbirdVer)
  exit(0);

if(version_is_less(version:thunderbirdVer ,test_version:"2.0.0.22")){
  report = report_fixed_ver(installed_version:thunderbirdVer, fixed_version:"2.0.0.22");
  security_message(port: 0, data: report);
}
