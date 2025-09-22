# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108683");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-10-22 09:14:32 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection (PPTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("pptp_detect.nasl");
  script_mandatory_keys("pptp/vendor_string/detected");

  script_tag(name:"summary", value:"PPTP based detection of MikroTik RouterOS.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:1723, proto:"pptp" );

if( ! banner = get_kb_item( "pptp/" + port + "/vendor_string" ) )
  exit( 0 );

if( banner !~ "MikroTik" )
  exit( 0 );

version = "unknown";

set_kb_item( name:"mikrotik/routeros/detected", value:TRUE );
set_kb_item( name:"mikrotik/routeros/pptp/detected", value:TRUE );
set_kb_item( name:"mikrotik/routeros/pptp/port", value:port );
set_kb_item( name:"mikrotik/routeros/pptp/" + port + "/concluded", value:banner );
set_kb_item( name:"mikrotik/routeros/pptp/" + port + "/version", value:version );

exit( 0 );
