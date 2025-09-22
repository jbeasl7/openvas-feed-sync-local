# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103663");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_name("RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57958");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-18 16:02:12 +0100 (Mon, 18 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"RaidSonic IB-NAS5220 and IB-NAS422-B are prone to multiple security
vulnerabilities, including:

1. An authentication-bypass vulnerability

2. An HTML-injection vulnerability

3. A command-injection vulnerability

The attacker may leverage these issues to bypass certain security
restrictions and perform unauthorized actions or execute HTML and
script code in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials, control how the site is rendered to the user, or inject
and execute arbitrary commands.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = '/login.cgi';
if(http_vuln_check(port:port, url:url,pattern:"<title>IB-NAS",check_header:TRUE, usecache:TRUE)) {

  url = '/cgi/user/user.cgi';
  if(http_vuln_check(port:port, url:url,pattern:"<option>admin</option>",check_header:TRUE)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
