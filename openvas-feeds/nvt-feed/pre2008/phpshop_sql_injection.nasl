# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:edikon:phpshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12022");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpShop Multiple Vulnerabilities (Jan 2004)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("gb_phpshop_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpshop/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/350026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9437");

  script_tag(name:"summary", value:"phpShop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Multiple vulnerabilities have been discovered in this product,
  which may allow a remote attacker to send arbitrary SQL commands to the remote database, or to
  insert malicious HTML and/or JavaScript into existing pages.");

  script_tag(name:"solution", value:"Update to the latest version of phpShop.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/?page=shop/cart&func=cartAdd&product_id='";

if( http_vuln_check( port:port, url:url, pattern:".*SQL.*item_enquiry_details.*auth=a" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
