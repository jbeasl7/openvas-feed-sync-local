# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801859");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0050");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CGI:IRC 'nonjs' Interface Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46303");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0346");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"CGI:IRC versions prior to 0.5.10.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'R' parameter in the 'nonjs' interface (interfaces/nonjs.pm), that
  allows attackers to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to CGI:IRC version 0.5.10 or later.");

  script_tag(name:"summary", value:"CGI:IRC is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/cgiirc", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:dir + "/irc.cgi",  port:port);
  if(">CGI:IRC Login<" >< res)
  {
    url = dir + "/irc.cgi?nick=" + vt_strings["default"] + "&interface=mozilla&R=<script>alert" +
                "('" + vt_strings["lowercase"] + "')</script>&item=fwindowlist";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"<script>alert\('" + vt_strings["lowercase"] + "'\)</script>"))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
