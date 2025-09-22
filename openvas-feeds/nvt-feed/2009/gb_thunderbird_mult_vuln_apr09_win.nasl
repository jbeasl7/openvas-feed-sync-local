# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900344");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305",
                "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities (Apr 2009) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34780");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34656");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-14.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-16.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-17.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-18.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Information Disclosure, XSS, Script
  Injection, Memory Corruption, CSRF, Arbitrary JavaScript code execution or
  can cause denial of service attacks.");
  script_tag(name:"affected", value:"Thunderbird version prior to 2.0.0.22 on Windows.");
  script_tag(name:"insight", value:"Please see the references for more information about the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version 2.0.0.22.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!tbVer)
  exit(0);

if(version_is_less(version:tbVer, test_version:"2.0.0.22")){
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"2.0.0.22");
  security_message(port: 0, data: report);
}
