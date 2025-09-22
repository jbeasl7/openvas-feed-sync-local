# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103181");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Trend Micro Data Loss Prevention Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");

  script_tag(name:"summary", value:"This host is running Trend Micro Data Loss Prevention, a network and
  endpoint-based data loss prevention (DLP) solution.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8443 );

url = "/dsc";
buf = http_get_cache( item:url + "/", port:port );
if( ! buf ) exit(0);

if( match = egrep( pattern:"<title>Trend Micro Data Loss Prevention Logon", string:buf, icase:TRUE ) ) {
  version = "unknown";
  set_kb_item( name:"trendmicro/datalossprevention/detected", value:TRUE );
  register_and_report_cpe( app:"Trend Micro Data Loss Prevention", ver:version, concluded:match, conclUrl:url, base:"cpe:/a:trend_micro:data_loss_prevention:", expr:"^([0-9.]+)", insloc:url, regPort:port, regService:"www" );
}

exit( 0 );
