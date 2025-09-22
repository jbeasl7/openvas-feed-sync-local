# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802448");
  script_version("2024-02-22T14:37:29+0000");
  script_cve_id("CVE-2012-2869", "CVE-2012-2868", "CVE-2012-2867", "CVE-2012-2866",
                "CVE-2012-2865", "CVE-2012-2872", "CVE-2012-2871", "CVE-2012-2870");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-09-03 15:01:42 +0530 (Mon, 03 Sep 2012)");
  script_name("Google Chrome < 21.0.1180.89 Multiple Vulnerabilities (Sep 2012) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50447");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55331");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/08/stable-channel-update_30.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 21.0.1180.89 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Out-of-bounds read in line breaking

  - Bad cast with run-ins.

  - Browser crash with SPDY.

  - Race condition with workers and XHR.

  - Avoid stale buffer in URL loading.

  - Lower severity memory management issues in XPath

  - Bad cast in XSL transforms.

  - XSS in SSL interstitial.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 21.0.1180.89 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"21.0.1180.89")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"21.0.1180.89");
  security_message(port:0, data:report);
}
