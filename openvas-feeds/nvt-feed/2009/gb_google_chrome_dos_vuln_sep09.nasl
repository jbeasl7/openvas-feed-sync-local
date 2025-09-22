# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900859");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7246");
  script_name("Google Chrome Denial Of Service Vulnerability (Sep 2009)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3194/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506328/100/100/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful attacks may result in Denial of Service condition on the victim's
  system.");
  script_tag(name:"affected", value:"Google Chrome version 0.2.149.29 and prior on Windows.");
  script_tag(name:"insight", value:"Error exists when application fails to handle user supplied input when calling
  the 'window.print' function in a loop aka a 'printing DoS attack'.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 4.1.249.1064 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"0.2.149.29")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Less than or equal to 0.2.149.29");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
