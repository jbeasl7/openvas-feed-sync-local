# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12077");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netscape Enterprise Server Default Files (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Netscape Enterprise Server has default files installed.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"These files should be removed as they may help an attacker to
  guess the exact version of the Netscape Server which is running on this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

report = 'The following default files were found:\n';

port = http_get_port(default:80);

foreach file(make_list("/help/contents.htm", "/manual/ag/contents.htm")) {

  buf = http_get_cache(item:file, port:port);
  if(!buf)
    continue;

  if("Netscape Enterprise Server Administrator's Guide" >< buf ||
     "Enterprise Edition Administrator's Guide" >< buf ||
     "Netshare and Web Publisher User's Guide" >< buf) {
    report += '\n' + file;
    vuln = TRUE;
  }
}

if(vuln) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
