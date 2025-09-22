# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108446");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-13 14:51:12 +0200 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("BeanShell Remote Server Mode RCE Vulnerability (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80); # No default port, assuming 80
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.beanshell.org/manual/remotemode.html");
  script_xref(name:"URL", value:"http://www.beanshell.org/manual/bshcommands.html#exec");

  script_tag(name:"summary", value:"The BeanShell Interpreter in remote server mode is prone to a
  remote code execution (RCE) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control
  over the target system.");

  script_tag(name:"vuldetect", value:"The script sends a HTTP GET request and checks if the BeanShell remote session
  console is available on the target host.");

  script_tag(name:"affected", value:"BeanShell Interpreter running in remote server mode.");

  script_tag(name:"solution", value:"Restrict access to the listener or disable the remote server mode.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/";
res = http_get_cache( port:port, item:url );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>BeanShell Remote Session</title>" >< res || "<h2>BeanShell Remote Session</h2>" >< res ) ) {
  security_message( port:port, data:"The BeanShell remote session console is available at the following URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
  exit( 0 );
}

exit( 99 );
