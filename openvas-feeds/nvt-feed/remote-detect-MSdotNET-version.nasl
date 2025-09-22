# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101007");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-03-15 21:21:09 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft dotNET (.NET) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Microsoft dotNET (.NET).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Microsoft dotNET (.NET) Detection (HTTP)";

port = http_get_port(default:80);
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

# request a non existent random page
page = string("/" + rand() + ".aspx");

request = http_get(item:page, port:port);
response = http_keepalive_send_recv(port:port, data:request, bodyonly:FALSE);

# a response example:
# Version Information: Microsoft .NET Framework Version:2.0.50727.1433; ASP.NET Version:2.0.50727.1433
dotNet_header = eregmatch(pattern:"Microsoft .NET Framework Version:([0-9.]+)",string:response, icase:TRUE);
aspNet_header = eregmatch(pattern:"ASP.NET Version:([0-9.]+)",string:response, icase:TRUE);

if(('Version Information' >< response) && dotNet_header){

  report = "Detected " + dotNet_header[0];

  set_kb_item(name:"dotNET/install", value:TRUE);
  set_kb_item(name:"dotNET/port", value:port);
  set_kb_item(name:"dotNET/version", value:dotNet_header[1]);

  cpe = build_cpe(value:dotNet_header[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:.net_framework:");
  if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  if(aspNet_header >< response){
    report += " and " + aspNet_header[0];

    set_kb_item(name:"aspNET/installed", value:TRUE);
    set_kb_item(name:"aspNET/version", value:aspNet_header[1]);
  }

  log_message(port:port, data:report);
}

exit( 0 );
