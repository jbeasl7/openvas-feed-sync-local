# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170203");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-10-25 11:21:01 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology NAS / DiskStation Manager (DSM) Detection (mDNS)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("mdns_service_detection.nasl");
  script_require_udp_ports("Services/udp/mdns", 5353);
  script_mandatory_keys("mdns/info/vendor", "mdns/port_and_proto");

  script_tag(name:"summary", value:"mDNS based detection of Synology NAS devices, DiskStation
  Manager (DSM) OS and application.");

  exit(0);
}

include("host_details.inc");
include("synology_func.inc");

if( ! port_and_proto_list = get_kb_list( "mdns/port_and_proto" ) )
  exit( 0 );

foreach port_and_proto( port_and_proto_list ) {

  if( ! vendor = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/vendor" ) )
    continue;

  if( "Synology" >!< vendor )
    continue;

  # nb: In case of Synology, model is always advertised for the 5000/tpc service;
  # the model for _device_info service seems to always be Xserve, which does not help
  model = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/model" );
  if( ! model )
    continue;

  port = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/admin_port" );
  if( isnull( port ) )
    continue;
  # nb: Construct concluded header here due to variable 'port_and_proto' - otherwise we have to save that to KB also
  concluded = 'mDNS on port ' + port_and_proto + " exposing service for " + port + "/tcp";
  concluded += '\n  Concluded:';
  concluded += '\n    - Service:       _http._tcp.local';
  concluded += '\n    - Vendor:        ' + vendor;
  concluded += '\n    - Model:         ' + model;

  product = "dsm";
  # nb: mDNS looks the same for NAS and router devices from Synology
  # we need to filter by router models
  if( check_is_synology_router( model:model ) ) {
    product = "srm";

    # nb: It seems that build number is actually accurate, while version_minor and version_major are bogus
    build_nr = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/version_build" );
    if( build_nr ) {
      version = synology_srm_build_number_to_full_version( buildNumber:build_nr );
      set_kb_item( name:"synology/srm/mdns/" + port + "/version", value:version );
      concluded += '\n    - Build number:  ' + build_nr;
    }
  } else {
    build_nr = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/version_build" );
    if( ! isnull( build_nr ) ) {
      version = synology_dsm_build_number_to_full_version( buildNumber:build_nr );
      concluded += '\n    - Build number:  ' + build_nr;

      major_vers = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/version_major" );
      # nb: version collected this way is less exact, as there is no micro part of it (although it is not always present)
      if( ! isnull( major_vers ) )
        concluded += '\n    - Major version: ' + major_vers;

      minor_vers = get_kb_item( "mdns/" + port_and_proto + "/services/_http._tcp.local/info/version_minor" );
      if( ! isnull( minor_vers ) )
        concluded += '\n    - Minor version: ' + minor_vers;

      set_kb_item( name:"synology/dsm/mdns/" + port + "/version", value:version );
    }
  }

  set_kb_item( name:"synology/" + product + "/detected", value:TRUE );
  set_kb_item( name:"synology/" + product + "/mdns/detected", value:TRUE );
  set_kb_item( name:"synology/" + product + "/mdns/port", value:port );
  set_kb_item( name:"synology/" + product + "/mdns/" + port + "/model", value:model );
  set_kb_item( name:"synology/" + product + "/mdns/" + port + "/concluded", value:concluded );
}

exit( 0 );
