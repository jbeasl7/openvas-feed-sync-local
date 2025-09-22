# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801851");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin < 3.4.0 beta 3 'db' Parameter Stored XSS Vulnerability - Active Check");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/97906/phpMyAdmin-3.4.x-Stored-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"http://bl0g.yehg.net/2011/01/phpmyadmin-34x-340-beta-2-stored-cross.html");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to plant XSS backdoors and
  inject arbitrary SQL statements via crafted XSS payloads.");
  script_tag(name:"affected", value:"phpMyAdmin versions 3.4.x before 3.4.0 beta 3.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed in
  the 'db' parameter to 'index.php', which allows attackers to execute arbitrary
  HTML and script code on the web server.");
  script_tag(name:"solution", value:"Update to version 3.4.0 beta 3 or later.");
  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php?db=%27%22--%3E%3C%2Fscript%3E%3Cscript%3Ealert%28%2FXSS%2F%29%3C%2Fscript%3E";

if(buf = http_vuln_check(port:port, url:url, pattern:"<script>alert\(/XSS/\)</",
                         check_header:TRUE)) {
  if('\"--' >< buf)
    exit(99); # db:"\'\"--></' + 'script><script>alert(/XSS/)</' + 'script>",token: <- because of the \' and \" version 4.0.4.1 is NOT vulnerable

  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
