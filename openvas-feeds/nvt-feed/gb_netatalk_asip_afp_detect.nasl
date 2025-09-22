# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108527");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2019-01-08 09:37:20 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Netatalk Detection (AppleShare IP / AFP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("asip-status.nasl");
  script_mandatory_keys("asip_afp/banner/available");

  script_xref(name:"URL", value:"http://netatalk.sourceforge.net/");

  script_tag(name:"summary", value:"AppleShare IP / AFP based detection of Netatalk.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port( default:548, proto:"appleshare" );

banner = get_kb_item( "asip_afp/" + port + "/banner" );
if( ! banner || banner !~ "^Netatalk" )
  exit( 0 );

version = "unknown";
install = port + "/tcp";

# Netatalk3.0.5
# Netatalk3-0-1-p5
# Netatalk 2.2.0
# Netatalk 2-2-0-p6
vers = eregmatch( string:banner, pattern:"^Netatalk ?([0-9.p-]+)" );
if( vers[1] )
  version = str_replace( string:vers[1], find:"-", replace:"." );

set_kb_item( name:"netatalk/detected", value:TRUE );

register_and_report_cpe( app:"Netatalk", ver:version, concluded:banner, base:"cpe:/a:netatalk:netatalk:", expr:"([0-9.p]+)", insloc:install, regPort:port, regService:"appleshare" );

exit( 0 );
