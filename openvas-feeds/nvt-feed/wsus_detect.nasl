# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20377");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Server Update Services (WSUS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 8530);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.microsoft.com/windowsserversystem/updateservices/default.mspx");

  script_tag(name:"summary", value:"HTTP based detection of Windows Server Update Services (WSUS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8530 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

res = http_get_cache( item:"/WsusAdmin/Errors/BrowserSettings.aspx", port:port );
if(!res)
  exit(0);

if( egrep( pattern:'<title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"', string:res ) ||
    egrep( pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:res ) ) {
  log_message( port:port );
}

exit( 0 );
