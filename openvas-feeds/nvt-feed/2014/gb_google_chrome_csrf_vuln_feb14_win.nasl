# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804316");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2013-6166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-02-17 17:40:48 +0530 (Mon, 17 Feb 2014)");
  script_name("Google Chrome CSRF Vulnerability - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to a cross-site request forgery (CSRF)
  attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of 'HTTP Cookie headers' for
restricted character-set.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct the
equivalent of a persistent Logout cross-site request forgery (CSRF) attack.");
  script_tag(name:"affected", value:"Google Chrome version prior to 29 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 29 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/117");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/04/03/10");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=238041");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"29.0"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"29.0");
  security_message(port:0, data:report);
  exit(0);
}
