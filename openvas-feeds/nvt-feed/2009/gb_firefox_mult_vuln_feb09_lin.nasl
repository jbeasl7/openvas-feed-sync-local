# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900309");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355",
                "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Feb 2009) - Linux");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33598");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in bypassing certain security restrictions,
  information disclosures, JavaScript code executions which can be executed with
  the privileges of the signed users.");
  script_tag(name:"affected", value:"Firefox version 2.x to 3.0.5 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Cookies marked 'HTTPOnly' are readable by JavaScript through the request
    calls of XMLHttpRequest methods i.e. XMLHttpRequest.getAllResponseHeaders
    and XMLHttpRequest.getResponseHeader.

  - Using local internet shortcut files to access other sites could be
    bypassed by redirecting to a privileged 'about:' URI e.g. 'about:plugins'.

  - Chrome XBL methods can be used to execute arbitrary Javascripts within the
    context of another website through the same origin policy by using
    'window.eval' method.

  - 'components/sessionstore/src/nsSessionStore.js' file does not block the
    changes of INPUT elements to type='file' during tab restoration.

  - Error in caching certain HTTP directives which is being ignored by Firefox
    which can expose sensitive data in any shared network.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.6.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_in_range(version:ffVer, test_version:"2.0", test_version2:"3.0.5")){
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"2.0 - 3.0.5");
  security_message(port: 0, data: report);
}
