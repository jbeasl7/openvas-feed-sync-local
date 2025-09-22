# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900214");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6994", "CVE-2008-6995", "CVE-2008-6996",
                "CVE-2008-6997", "CVE-2008-6998");
  script_name("Google Chrome < 0.2.149.29 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30983");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31038");
  script_xref(name:"URL", value:"http://evilfingers.com/advisory/google_chrome_poc.php");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020823.html");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - the Browser failing to handle specially crafted HTML img tags, certain
    user-supplied data, HTTP view-source headers, and HTML href tags.

  - the Browser allows users to download arbitrary files without confirmation.

  - the Browser fails to perform adequate validation on user supplied data.");

  script_tag(name:"affected", value:"Google Chrome version 0.2.149.27 and prior.");

  script_tag(name:"solution", value:"Update to version 0.2.149.29 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"impact", value:"A remote user could cause Denial of Service conditions or can execute arbitrary
  code by convincing the users to visit a malicious website.");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer)
  exit(0);

if(version_is_less(version:chromeVer, test_version:"0.2.149.29")) {
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Less than 0.2.149.29");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
