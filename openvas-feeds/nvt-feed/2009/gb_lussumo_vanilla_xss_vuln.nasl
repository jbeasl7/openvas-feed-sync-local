# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lussumo:vanilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800623");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1845");
  script_name("Vanilla <= 1.1.7 'RequestName' XSS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lussumo_vanilla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Lussumo/Vanilla/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35114");
  script_xref(name:"URL", value:"http://gsasec.blogspot.com/2009/05/vanilla-v117-cross-site-scripting.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an
  affect site and it result XSS attack.");

  script_tag(name:"affected", value:"Lussumo Vanilla 1.1.7 and prior on all running platform.");

  script_tag(name:"insight", value:"Error is due to improper sanitization of user supplied input
  in the 'RequestName' parameter in '/ajax/updatecheck.php' file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Lussumo Vanilla is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

ver = infos["version"];
dir = infos["location"];
install = dir;
if( dir == "/" ) dir = "";

if( ! safe_checks() ) {
  url = dir + "/ajax/updatecheck.php?PostBackKey=1&ExtensionKey=1&RequestName=1<script>alert(Exploit-XSS)</script>";
  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );
  if( res =~ "^HTTP/1\.[01] 200" && "Exploit-XSS" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( ver && version_is_less_equal( version:ver, test_version:"1.1.8" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"None", install_path:install );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
