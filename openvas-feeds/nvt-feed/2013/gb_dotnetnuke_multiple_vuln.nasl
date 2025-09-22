# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803874");
  script_version("2025-07-22T05:43:35+0000");
  script_cve_id("CVE-2013-3943", "CVE-2013-4649", "CVE-2013-7335");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-08-21 15:43:57 +0530 (Wed, 21 Aug 2013)");
  script_name("DotNetNuke 6.x < 6.2.9, 7.x < 7.1.1 Redirection Weakness and XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dotnetnuke/http/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to redirection weakness and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input related to the 'Display Name' field in 'Manage Profile' is not properly sanitised before
  being used.

  - Input passed via the '__dnnVariable' GET parameter to Default.aspx is not properly sanitised
  before being returned to the user.

  - Certain unspecified input is not properly verified before being used to redirect users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insertion attacks and conduct
  spoofing and cross-site scripting attacks.");

  script_tag(name:"affected", value:"DotNetNuke versions 6.x prior 6.2.9 and 7.x prior to 7.1.1.");

  script_tag(name:"solution", value:"Update to version 6.2.9, 7.1.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53493");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61809");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080113");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122792");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53493");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

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

url = dir + "/?__dnnVariable={%27__dnn_pageload%27:%27alert%28document.cookie%29%27}";

## Extra check is not possible in this case.
if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"alert\(document\.cookie\)" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
