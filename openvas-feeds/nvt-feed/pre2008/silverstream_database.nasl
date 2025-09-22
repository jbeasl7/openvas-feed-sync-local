# SPDX-FileCopyrightText: 2002 Tor Houghton
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10847");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SilverStream database structure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Tor Houghton");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/101/144786");

  script_tag(name:"solution", value:"Reconfigure the server so that others
  cannot view database structure.");

  script_tag(name:"summary", value:"It is possible to download the remote SilverStream database
  structure by requesting :

  http://www.example.com/SilverStream/Meta/Tables/?access-mode=text");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more knowledge about
  this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = string("/SilverStream/Meta/Tables/?access-mode=text");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res && "_DBProduct" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
