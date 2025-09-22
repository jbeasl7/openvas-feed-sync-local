# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103660");
  script_cve_id("CVE-2013-0235");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2025-01-31T05:37:27+0000");

  script_name("WordPress < 3.5.1 Pingback Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57554");
  script_xref(name:"URL", value:"http://www.acunetix.com/blog/web-security-zone/wordpress-pingback-vulnerability/");

  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-02-07 10:52:18 +0100 (Thu, 07 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"WordPress is prone to an information disclosure vulnerability
  and multiple HTML injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials, control how the site is rendered to the user, and
  disclose or modify sensitive information. Other attacks are also possible.");

  script_tag(name:"affected", value:"WordPress versions prior to 3.5.1 are vulnerable.");

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

function _check(c, url, host, useragent) {

  local_var c, url, host, useragent, xml, len, req, result, value;

  xml = string('<?xml version="1.0" encoding="utf-8"?>', "\r\n",
               "<methodCall>\r\n",
               "<methodName>pingback.ping</methodName>\r\n",
               "<params>\r\n",
               "<param><value><string>http://", c, "</string></value></param>\r\n",
               "<param><value><string>http://", host, dir, "?p=1</string></value></param>\r\n",
               "</params>\r\n",
               "</methodCall>\r\n");

  len = strlen(xml);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Connection: Close\r\n",
               "Accept-Language: en\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               xml);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  value = eregmatch(pattern:"<value><string>([^<]+)</string></value>", string:result);
  if(!isnull(value[1])) return value[1];

  return FALSE;
}

url = dir + "/xmlrpc.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);
hostnoport = http_host_name(dont_add_port:TRUE);

if(!http_vuln_check(port:port, url:url, usecache:TRUE, pattern:"XML-RPC server accepts POST requests only"))
  exit(0);

if(!ret1 = _check(c:"i-dont-exist", url:url, host:host, useragent:useragent))
  exit(0);

if("The source URL does not exist" >< ret1) {

  tests = make_list("localhost:22", "localhost:25", hostnoport + ":" + port);
  foreach test (tests) {

    ret = _check(c:test, url:url, host:host, useragent:useragent);

    if("The source URL does not contain a link to the target URL" >< ret || "We cannot find a title on that page" >< ret) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
