# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12122");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1195");
  script_name("Novell Groupwise Servlet Manager Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3697");

  script_tag(name:"solution", value:"Change the default password

  Edit SYS:\JAVA\SERVLETS\SERVLET.PROPERTIES

  change the username and password in this section:

  servlet.ServletManager.initArgs=datamethod=POST, user=servlet, password=manager, bgcolor");

  script_tag(name:"summary", value:"The Novell Groupwise servlet server is configured with the default password.");

  script_tag(name:"impact", value:"As a result, users could be denied access to mail and other servlet
  based resources.");

  script_tag(name:"insight", value:"To test this finding:

  https://example.com/servlet/ServletManager/

  enter 'servlet' for the user and 'manager' for the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:443);

url = "/servlet/ServletManager";
req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", "Basic c2VydmxldDptYW5hZ2Vy"));
buf = http_keepalive_send_recv(port:port, data:req);
if(!buf)
  exit(0);

if("ServletManager" >< buf && "Servlet information" >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
