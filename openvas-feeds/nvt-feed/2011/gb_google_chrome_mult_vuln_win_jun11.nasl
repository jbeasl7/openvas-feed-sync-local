# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902392");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348",
                "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Vulnerabilities (Jun 2011) - Windows");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service, cross-site-scripting and execution of arbitrary code.");
  script_tag(name:"affected", value:"Google Chrome version prior to 12.0.742.112 on Windows.");
  script_tag(name:"insight", value:"The flaws are due to:

  - Error in 'NPAPI implementation', while handling the strings.

  - Use-after-free error in SVG font handling.

  - Memory corruption error while handling 'Cascading Style Sheets (CSS)'
    token sequences.

  - Incorrect bounds check in Google V8.

  - Use-after-free vulnerability, allows attackers to cause denial of service
    via vectors related to text selection.

  - Error in 'HTML' parser, while handling the address 'lifetime and
    re-entrancy issues'.

  - Use-after-free error with 'SVG' use element.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 12.0.742.112 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/06/stable-channel-update_28.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48479");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"12.0.742.112")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"12.0.742.112");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
