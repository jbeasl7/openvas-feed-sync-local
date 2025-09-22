# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802338");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-3640");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_name("Google Chrome Mozilla Network Security Services Privilege Escalation Vulnerability - Windows");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=641052");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=97426");
  script_xref(name:"URL", value:"http://blog.acrossecurity.com/2011/10/google-chrome-pkcs11txt-file-planting.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the local attacker to execute arbitrary
  code with an elevated privileges.");
  script_tag(name:"affected", value:"Google Chrome version 16.0.912.21 and prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in the Mozilla Network Security Services
  (NSS) library, which can be exploited by sending Trojan horse pkcs11.txt
  file in a top-level directory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a privilege escalation vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"16.0.912.21")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"Less than or equal to 16.0.912.21");
  security_message(port: 0, data: report);
}
