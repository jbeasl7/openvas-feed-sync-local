# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900419");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5749");
  script_name("Google Chrome Argument Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7566");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32997");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/499581/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code
  in the context of the web browser and can compromise the remote system
  by executing mailcious commands.");
  script_tag(name:"affected", value:"Google Chrome version 1.0.154.36 and prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to lack of sanitization check of user supplied input via

  - -renderer-path option in a chromehtml: URI.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 4.1.249.1064 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host has installed Google Chrome and is prone to argument
  injection vulnerability.");


  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.36")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Less than or equal to 1.0.154.36");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
