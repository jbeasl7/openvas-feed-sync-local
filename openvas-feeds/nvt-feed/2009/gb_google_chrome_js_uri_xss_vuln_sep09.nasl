# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800881");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3011");
  script_name("Google Chrome 'javascript: URI' XSS Vulnerability (Sep 2009)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3315/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct
Cross-Site Scripting attacks in the victim's system.");
  script_tag(name:"affected", value:"Google Chrome version 1.0.154.48 and prior, 2.0.172.28 and
2.0.172.37, and 3.0.193.2 Beta on Windows.");
  script_tag(name:"insight", value:"Google Chrome fails to sanitise the 'javascript:' and 'data:'
URIs in Refresh headers in HTTP responses, which can be exploited via vectors
related to injecting a Refresh header.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Google Chrome Web Browser is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(isnull(chromeVer))
{
  exit(0);
}

#                                and 3.0.193.2 Beta
if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.48")||
   version_is_equal(version:chromeVer, test_version:"2.0.172.37")||
   version_is_equal(version:chromeVer, test_version:"2.0.172.28")||
   version_is_equal(version:chromeVer, test_version:"3.0.193.2")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}

exit(99);
