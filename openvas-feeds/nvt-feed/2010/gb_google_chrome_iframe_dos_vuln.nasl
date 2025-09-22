# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902184");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1992", "CVE-2010-2120");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome 'IFRAME' Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4206/");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4238/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511327/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
denial of service.");
  script_tag(name:"affected", value:"Google Chrome version 1.0.154.48 and prior.");
  script_tag(name:"insight", value:"The flaw is due to:

  - Improper handling of an 'IFRAME' element with a mailto: URL in its 'SRC'
attribute, which allows remote attackers to consume resources via an HTML
document with many 'IFRAME' elements.

  - JavaScript code, containing an infinite loop which creates 'IFRAME' elements
for invalid 'news:// URIs'.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 6.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.48")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Less than or equal to 1.0.154.48");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
