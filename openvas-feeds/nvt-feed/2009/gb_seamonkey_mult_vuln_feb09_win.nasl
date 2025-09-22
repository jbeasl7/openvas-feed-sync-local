# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900312");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0356",
                "CVE-2009-0357");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities (Feb 2009) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33598");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in bypassing certain security
  restrictions, information disclosures, JavaScript code executions which
  can be executed with the privileges of the signed users.");
  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.15 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Vectors related to the layout engine and destruction of arbitrary layout
    objects by the 'nsViewManager::Composite' function.

  - Cookies marked 'HTTPOnly' are readable by JavaScript through the request
    calls of XMLHttpRequest methods i.e. XMLHttpRequest.getAllResponseHeaders
    and XMLHttpRequest.getResponseHeader.");
  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.15.");
  script_tag(name:"summary", value:"Mozilla Seamonkey browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");
if(!smVer){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"1.1.15")){
  report = report_fixed_ver(installed_version:smVer, fixed_version:"1.1.15");
  security_message(port: 0, data: report);
}
