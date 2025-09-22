# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800227");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Reflection for Secure IT Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/reflection/secureit/detected");

  script_tag(name:"summary", value:"The script tries to detect Reflections for Secure IT and its
  version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );
if( ! banner || banner !~ "^SSH\-.*ReflectionForSecureIT" )
  exit( 0 );

set_kb_item( name:"attachmate/reflection_for_secure_it/detected", value:TRUE );

version = "unknown";
install = port + "/tcp";

vers = eregmatch( pattern:"SSH\-.*ReflectionForSecureIT_([0-9.]+)", string:banner );
if( vers[1] )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:attachmate:reflection_for_secure_it:");
if( ! cpe )
  cpe = "cpe:/a:attachmate:reflection_for_secure_it";

register_product( cpe:cpe, location:install, port:port, service:"ssh" );

log_message( data:build_detection_report(app:"Reflection for Secure IT",
                                         version:version,
                                         install:install,
                                         cpe:cpe,
                                         concluded:banner),
                                         port:port );

exit( 0 );
