# SPDX-FileCopyrightText: 2006 Josh Zlatin-Amishav
# SPDX-FileCopyrightText: Detection methodology got largely rewritten by Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19601");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus / HP / HPE (OpenView Storage) Data Protector Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_family("Product detection");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_dependencies("find_service1.nasl", "find_service2.nasl");

  script_tag(name:"summary", value:"TCP based detection of Mirco Focus / HP / HPE (OpenView Storage)
  Data Protector.");

  script_xref(name:"URL", value:"https://www.microfocus.com/en-us/products/data-protector-backup-recovery-software/overview");

  exit(0);
}

include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = service_get_port( default:5555, proto:"hp_dataprotector" );

if( ! banner = get_kb_item( "hp_dataprotector/" + port + "/banner" ) ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  # Data Protector can take some time to return its header
  banner = recv( socket:soc, length:4096, timeout:20 );
  close( soc );
}

if( banner && banner =~ "^(Micro Focus|HPE?) (OpenView Storage )?Data Protector" ) {

  version = "unknown";
  build = "unknown";
  install = "/";

  # HP Data Protector A.06.10: INET, internal build 611, built on 2008
  # HPE Data Protector A.09.09: INET, internal build 114, built on Tuesday, March 28, 2017, 5:02 PM
  # HPE Data Protector A.09.09: INET, internal build 115, built on Dienstag, 23. Mai 2017, 22:16
  # HP OpenView Storage Data Protector A.06.00: INET, internal build 331
  # HP OpenView Storage Data Protector A.05.50: INET, internal build 330
  # HP OpenView Storage Data Protector A.05.00: INET, internal build 190, built on Tue Jul 16 17:37:32 2002.
  # Micro Focus Data Protector A.10.03: INET, internal build 181, built on Sunday, March 25, 2018, 6:32 PM
  vers = eregmatch( pattern:"Data Protector ([^:]+)", string:banner );
  if( vers[1] )
    version = vers[1];

  bld = eregmatch( pattern:"internal build ([^,]+)", string:banner );
  if( bld[1] )
    build = bld[1];

  # nb: In case the service wasn't identified before
  service_register( port:port, proto:"hp_dataprotector" );

  set_kb_item( name:"microfocus/data_protector/detected", value:TRUE );
  set_kb_item( name:"microfocus/data_protector/" + port + "/build", value:build );

  cpe1 = build_cpe( value:version, exp:"^[a-zA-Z]\.([0-9.]+)", base:"cpe:/a:hp:data_protector:" );
  cpe2 = build_cpe( value:version, exp:"^[a-zA-Z]\.([0-9.]+)", base:"cpe:/a:hpe:data_protector:" );
  cpe3 = build_cpe( value:version, exp:"^[a-zA-Z]\.([0-9.]+)", base:"cpe:/a:microfocus:data_protector:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:hp:data_protector";
    cpe2 = "cpe:/a:hpe:data_protector";
    cpe3 = "cpe:/a:microfocus:data_protector";
  }

  register_product( cpe:cpe1, location:install, port:port, service:"hp_dataprotector" );
  register_product( cpe:cpe2, location:install, port:port, service:"hp_dataprotector" );
  register_product( cpe:cpe3, location:install, port:port, service:"hp_dataprotector" );

  log_message( data:build_detection_report( app:"Micro Focus / HP / HPE (OpenView Storage) Data Protector",
                                            version:version,
                                            build:build,
                                            install:install,
                                            cpe:cpe3,
                                            concluded:chomp( banner ) ),
               port:port );
}

exit( 0 );
