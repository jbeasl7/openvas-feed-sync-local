# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802126");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2761");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome 'GetWidget' methods DoS Vulnerability - Windows");
  script_xref(name:"URL", value:"http://codereview.chromium.org/7189019");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=86119");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/06/dev-channel-update_16.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause denial-of-service
  via a crafted web site, related to GetWidget methods.");
  script_tag(name:"affected", value:"Google Chrome version 14.0.792.0");
  script_tag(name:"insight", value:"The flaw is due to error while handling a reload of a page generated
  in response to a POST which allows remote attackers to cause a denial of
  service.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 14.0.794.0 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_equal(version:chromeVer, test_version:"14.0.792.0")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Equal to 14.0.792.0");
  security_message(port: 0, data: report);
}
