# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105624");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-04-26 12:59:19 +0200 (Tue, 26 Apr 2016)");
  script_name("Cisco Finesse Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Finesse.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/desktop/container/";
buf = http_get_cache( item:url, port:port );

if( ">Sign in to Cisco Finesse</title>" >< buf && "j_security_check" >< buf && "Cisco Systems, Inc" >< buf ) {
  cpe = "cpe:/a:cisco:finesse";
  register_product( cpe:cpe, location:url, port:port, service:"www" );
  log_message( port:port, data:'The Cisco Finesse Webinterface is running at this port.\nCPE: ' + cpe + '\nLocation: /desktop/' );
}

exit( 0 );
