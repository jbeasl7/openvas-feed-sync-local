# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900860");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3264");
  script_name("Google Chrome 'getSVGDocument' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36416");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=21338");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/09/stable-channel-update.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks
  on the victim's system via SVG document.");
  script_tag(name:"affected", value:"Google Chrome version prior to 3.0.195.21 on Windows.");
  script_tag(name:"insight", value:"Error exists when 'getSVGDocument' method omits an unspecified access check
  which can be exploited by remote web servers to bypass the Same Origin
  Policy and conduct XSS attacks via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to Google Chrom version 3.0.195.21 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to a cross-site scripting (XSS) vulnerability.");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"3.0.195.21")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"3.0.195.21");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
