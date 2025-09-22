# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802717");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3046");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-20 11:56:00 +0530 (Tue, 20 Mar 2012)");
  script_name("Google Chrome 'History navigation' Arbitrary Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48321/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52369");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/03/chrome-stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.zdnet.com/blog/security/cansecwest-pwnium-google-chrome-hacked-with-sandbox-bypass/10563");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.78 on Windows");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors when handling certain
  JavaScript and navigating history.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.78 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to an arbitrary code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.78")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"17.0.963.78");
  security_message(port:0, data:report);
}
