# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113242");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Autonomic Controls Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection for Autonomic Controls devices using HTTP.");

  script_xref(name:"URL", value:"http://www.autonomic-controls.com/products/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );

if( banner && banner =~ 'Autonomic Controls' ) {

  set_kb_item( name: "autonomic_controls/detected", value: TRUE );
  set_kb_item( name: "autonomic_controls/http/port", value: port );

  ver = eregmatch( string: banner, pattern: 'Autonomic Controls/([0-9.]+)', icase: TRUE );
  if( ! isnull( ver[1] ) ) {
    set_kb_item( name: "autonomic_controls/http/version", value: ver[1] );
    set_kb_item( name: "autonomic_controls/http/concluded", value: ver[0] );
  }
}

exit( 0 );
