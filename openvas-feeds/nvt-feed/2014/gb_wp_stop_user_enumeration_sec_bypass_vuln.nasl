# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804084");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-05 13:09:46 +0530 (Wed, 05 Feb 2014)");
  script_name("WordPress Stop User Enumeration Security Bypass Vulnerability");

  script_tag(name:"summary", value:"WordPress Stop User Enumeration Plugin is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to
bypass security restriction or not.");
  script_tag(name:"insight", value:"Username enumeration protection for 'author' parameter via POST request
is not proper.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to enumerate users and get some
sensitive information, leads to further attacks.");
  script_tag(name:"affected", value:"WordPress Stop User Enumeration Plugin version 1.2.4, Other versions may also
be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/3");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/56643");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0003.html");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-stop-user-enumeration-124-bypass");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
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

url = dir + "/wp-content/plugins/stop-user-enumeration/stop-user-enumeration.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

if(http_vuln_check(port:port, url:url, check_header:TRUE, usecache:TRUE,
   pattern:"<b>Fatal error</b>:  Call to undefined function is_admin\(\).*stop-user-enumeration\.php</b>")) {

  url2 = dir + "/index.php?author=1";

  if(http_vuln_check(port:port, url:url2, check_header:"FALSE",
     pattern:"^HTTP/1\.[01] 500", extra_check:">forbidden<")) {

    req = string("POST ", dir, "/index.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: 8\r\n",
                 "\r\nauthor=1\r\n");
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && ">forbidden<" >!< res &&
       res !~ "^HTTP/1\.[01] 500") {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(99);
}

exit(0);
