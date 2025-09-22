# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902050");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_cve_id("CVE-2010-1502", "CVE-2010-1767", "CVE-2010-1500", "CVE-2010-1503",
                "CVE-2010-1504", "CVE-2010-1505", "CVE-2010-1506");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome 4.1.249.1059 Multiple Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39603");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/04/stable-update-security-fixes.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information,
  execute arbitrary code in the context of the browser, bypass certain security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 4.1.249.1059 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Type confusion error with 'forms'

  - An unspecified error in the handling of 'HTTP requests', which leads to
  cross-site request forgery attacks.

  - An error related to 'chrome://net-internals' and 'chrome://downloads',
  which leads to cross-site scripting attacks

  - Error related to local file references through 'developer tools'

  - Pages that might load with privileges of the 'New Tab page'.

  - An unspecified error in 'V8 bindings' causes a denial of service.");

  script_tag(name:"solution", value:"Upgrade to the version 9501.942.1.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Google Chrome Web Browser is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

if(version_is_less(version:gcVer, test_version:"4.1.249.1059")){
  report = report_fixed_ver(installed_version:gcVer, fixed_version:"4.1.249.1059");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
