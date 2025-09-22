# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170226");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-11-14 22:03:50 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology DiskStation Manager (DSM) Detection (UPnP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_upnp_tcp_detect.nasl");
  script_mandatory_keys("upnp/tcp/port");

  script_tag(name:"summary", value:"UPnP based detection of Synology NAS devices, DiskStation Manager
  (DSM) OS and application.");

  exit(0);
}

include("host_details.inc");
include("synology_func.inc");

if ( ! ports = get_kb_list( "upnp/tcp/port" ) )
  exit( 0 );

foreach port( ports ) {

  if( ! vendor = get_kb_item( "upnp/tcp/" + port + "/device/manufacturer" ) )
    exit( 0 );

  if( "Synology" >< vendor ) {

    concluded  = '\n    - Manufacturer: ' + vendor;
    model_nr = get_kb_item( "upnp/tcp/" + port + "/device/modelNumber" );
    if( model_nr ) {
      concluded  += '\n    - Model:        ' + model_nr;
      # DS212j 6.2-25556
      # FS3400 7.2-69057
      info = split( model_nr, sep:" ", keep:FALSE );
      model = info[0];
      if( model ) {
        product = "dsm";
        # nb: UPnP looks the same for NAS and router devices from Synology
        # we need to filter by router models
        if( check_is_synology_router( model:model ) ) {
          product = "srm";
        } else {
          # nb: Version for router (SRM OS) exposed via mDNS is not correct, only extract for DSM
          if( info[1] ) {
            vers = split( info[1], sep:"-", keep:FALSE );
            # nb: UPnP has incomplete version therefore we use build number to map to correct one
            if ( vers[1] ) {
              version = synology_dsm_build_number_to_full_version( buildNumber:vers[1] );
              set_kb_item( name:"synology/dsm/upnp/" + port + "/version", value:version );
            }
          }
        }

        set_kb_item( name:"synology/" + product + "/detected", value:TRUE );
        set_kb_item( name:"synology/" + product + "/upnp/detected", value:TRUE );
        set_kb_item( name:"synology/" + product + "/upnp/port", value:port );
        set_kb_item( name:"synology/" + product + "/upnp/" + port + "/model", value:model );
        set_kb_item( name:"synology/" + product + "/upnp/" + port + "/concluded", value:concluded );
      }
    }
  }
}

exit( 0 );
