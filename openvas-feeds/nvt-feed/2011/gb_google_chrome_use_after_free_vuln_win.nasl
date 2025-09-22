# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901190");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-1059");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome Use-After-Free Vulnerability - Windows");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=52819");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=70315");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/dev-channel-update_17.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.672.2 on windows");
  script_tag(name:"insight", value:"An use-after-free error in WebCore in WebKit allows user-assisted remote
  attackers to cause a denial of service or possibly have unspecified other
  impact via vectors that entice a user to resubmit a form, related to improper
  handling of provisional items by the HistoryController component.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 11.0.672.2 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a use after free vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.672.2")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.672.2");
  security_message(port: 0, data: report);
}
