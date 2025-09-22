# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804054");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-01-02 15:02:10 +0530 (Thu, 02 Jan 2014)");
  script_name("WordPress WP Realty Plugin 'listing_id' XSS and SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"WordPress WP Realty Plugin is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"insight", value:"Input passed via the 'listing_id' parameter to index_ext.php script is
not properly sanitized before being returned to the user.");
  script_tag(name:"affected", value:"WordPress WP Realty plugin.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site
or execute arbitrary SQL commands in applications database and gain complete
control over the vulnerable web application.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29021");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124418");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-wp-realty-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
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

url = dir + '/wp-content/plugins/wp-realty/index_ext.php?action='+
            'contact_friend&popup=yes&listing_id="/><script>aler'+
                                   't(document.cookie);</script>';

## Extra check is not possible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\);</script>"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
