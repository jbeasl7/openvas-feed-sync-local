# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902616");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2008-7294");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Google Chrome Secure Cookie Security Bypass Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49133");
  script_xref(name:"URL", value:"http://michael-coates.blogspot.com/2010/01/cookie-forcing-trust-your-cookies-no.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to overwrite or delete arbitrary
  cookies by sending a specially crafted HTTP response through a man-in-the-
  middle attack.");
  script_tag(name:"affected", value:"Google Chrome version prior to 4.0.211.0 on Mac OS X.");
  script_tag(name:"insight", value:"The flaw is due to improper restrictions for modifications to cookies
  established in HTTPS sessions i.e lack of the HTTP Strict Transport Security
  (HSTS) includeSubDomains feature, which allows man-in-the-middle attackers
  to overwrite or delete arbitrary cookies via a Set-Cookie header in an HTTP
  response.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 4.0.211.0 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a security bypass vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"4.0.211.0")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"4.0.211.0");
  security_message(port: 0, data: report);
}
