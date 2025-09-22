# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10265");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("An SNMP Agent is running");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("SNMP");
  script_dependencies("gb_open_udp_ports.nasl", "gb_snmp_authorization.nasl", "snmp_default_communities.nasl");
  script_require_udp_ports("Services/udp/unknown", 161);

  script_tag(name:"summary", value:"This script detects if SNMP is open and if it is possible to
  connect with the given credentials / community string from one of the following resources:

  - SNMPv1/2 community string provided via the target configuration or via 'SNMP Authorization (OID:
  1.3.6.1.4.1.25623.1.0.105076).'

  - SNMPv1/2 community string detected by 'Check default community names of the SNMP Agent (OID:
  1.3.6.1.4.1.25623.1.0.103914).'

  - SNMPv3 credentials provided via the target configuration or via 'SNMP Authorization (OID:
  1.3.6.1.4.1.25623.1.0.105076).'");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("list_array_func.inc");
include("snmp_func.inc");
include("host_details.inc");
include("misc_func.inc");

# nb: This is used later to report to the user if the login with the provided community failed
global_var provided_community;

function _create_community_list( port ) {

  local_var port, communities, detected_community, detected_communities;

  communities = make_array();

  # First choose the community provided by the user, this is one single item
  provided_community = get_kb_item( "SNMP/v12c/provided_community" );
  if( provided_community && strlen( provided_community ) > 0 )
    communities[provided_community] = "v12c_provided_creds";

  # Fallback for default communities detected by snmp_default_communities.nasl. This could have multiple items.
  # Also make sure that we're not using a huge list of communities if the remote device is broken.
  if( ! get_kb_item( "SNMP/" + port + "/v12c/all_communities" ) ) {
    detected_communities = get_kb_list( "SNMP/" + port + "/v12c/detected_community" );
    foreach detected_community( detected_communities ) {
      if( array_key_exist( key:detected_community, array:communities, part_match:FALSE, bin_search:FALSE, icase:FALSE ) )
        communities[detected_community] = "v12c_provided_nd_detected_creds";
      else
        communities[detected_community] = "v12c_detected_creds";
    }
  }

  # Final fallback to 'public' if none of the above applied
  if( max_index( keys( communities ) ) == 0 )
    communities["public"] = "v12c_pub_comm";

  return communities;
}

# Scanner needs to be build against libsnmp or have snmpget installed for extended SNMP
# functionality in e.g. snmp_func.inc.
# nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
# https://github.com/greenbone/openvas-scanner/pull/594
if( defined_func( "snmpv3_get" ) ) {

  port = unknownservice_get_port( default:161, ipproto:"udp" );

  provided_comm_report     = 'It was possible to log in using the community string provided via the target configuration or via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076)".\n';
  default_comm_report      = 'It was possible to log in using the default community string \'public\'.\n';
  failed_comm_report       = 'It was NOT possible to log in using the community string provided via the target configuration or via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076)".\n';
  detected_comm_report_pre = 'It was possible to log in using the community string ';
  detected_comm_report     = ' detected by "Check default community names of the SNMP Agent (OID: 1.3.6.1.4.1.25623.1.0.103914)".\n';
  additional_info_report   = "";

  communities = _create_community_list( port:port );

  foreach community( keys( communities ) ) {

    if( snmp_check_v1( port:port, community:community ) ) {

      # worked with provided community string
      if( communities[community] == "v12c_provided_creds" || communities[community] == "v12c_provided_nd_detected_creds" ) {
        additional_info_report += "- SNMPv1: " + provided_comm_report;
        snmpv1_provided_comm_worked = TRUE;
      }

      # worked with default community string 'public'
      if( communities[community] == "v12c_pub_comm" )
        additional_info_report += "- SNMPv1: " + default_comm_report;

      # worked with detected community string
      if( communities[community] == "v12c_detected_creds" || communities[community] == "v12c_provided_nd_detected_creds" )
        additional_info_report += "- SNMPv1: " + detected_comm_report_pre + "'" + community + "'" + detected_comm_report;

      # TBD: Set only one community?
      set_kb_item( name:"SNMP/" + port + "/v1/community", value:community );

      # We don't need to set those keys multiple times
      if( ! SNMP_v1 ) {
        SNMP_v1 = TRUE;
        set_kb_item( name:"SNMP/" + port + "/v1/working", value:TRUE );
        set_kb_item( name:"SNMP/" + port + "/working", value:TRUE );
        replace_kb_item( name:"SNMP/" + port + "/preferred_version", value:1 );
      }
    }

    if( snmp_check_v2( port:port, community:community ) ) {

      # worked with provided community string
      if( communities[community] == "v12c_provided_creds" || communities[community] == "v12c_provided_nd_detected_creds" ) {
        additional_info_report += "- SNMPv2c: " + provided_comm_report;
        snmpv2c_provided_comm_worked = TRUE;
      }

      # worked with default community string 'public'
      if( communities[community] == "v12c_pub_comm" )
        additional_info_report += "- SNMPv2c: " + default_comm_report;

      # worked with detected community string
      if( communities[community] == "v12c_detected_creds" || communities[community] == "v12c_provided_nd_detected_creds" )
        additional_info_report += "- SNMPv2c: " + detected_comm_report_pre + "'" + community + "'" + detected_comm_report;

      # TBD: Set only one community?
      set_kb_item( name:"SNMP/" + port + "/v2c/community", value:community );

      # We don't need to set those keys multiple times
      if( ! SNMP_v2c ) {
        SNMP_v2c = TRUE;
        set_kb_item( name:"SNMP/" + port + "/v2c/working", value:TRUE );
        set_kb_item( name:"SNMP/" + port + "/working", value:TRUE );
        replace_kb_item( name:"SNMP/" + port + "/preferred_version", value:2 );
      }
    }
  }

  v3check = snmp_check_v3( port:port );
  # nb: In case of a successful login
  if( v3check == 1 ) {
    SNMP_v3 = TRUE;
    set_kb_item( name:"SNMP/" + port + "/v3/working", value:TRUE );
    set_kb_item( name:"SNMP/" + port + "/working", value:TRUE );
    replace_kb_item( name:"SNMP/" + port + "/preferred_version", value:3 );
  }

  # nb:
  # - This happens if we actually have found a SNMPv3 service via the error messages reported by it
  #   back to us (the ones defined in valid_snmpv3_errors of snmp_func.inc)
  # - In this case we're not setting the KB keys like done in the previous case because the login
  #   didn't worked and we want to fallback to a possible earlier SNMPv2 version if that worked
  else if( v3check == 2 ) {
    SNMP_v3 = TRUE;
  }

  # Some SNMP devices (namely Huawei Versatile Routing Platform Software, Version 5.160)
  # can't handle subsequent SNMP requests if a login via SNMPv3 failed. We want to do
  # a sleep for such devices here to avoid that e.g. gb_snmp_info_collect.nasl is failing
  # to detect the SNMP sysDescr via SNMPv1/2.
  sleep( 5 );

  # Notify the user if the provided community string did not work
  if( ! snmpv1_provided_comm_worked && ! snmpv2c_provided_comm_worked && provided_community && strlen( provided_community ) > 0 ) {
    additional_info_report += "- SNMPv1|v2c: " + failed_comm_report;
    set_kb_item( name:"login/SNMP/failed", value:TRUE );
    set_kb_item( name:"login/SNMP/failed/port", value:port );
    register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp, Community " + provided_community + " : Login failure" );
  } else if( provided_community && strlen( provided_community ) > 0 && ( snmpv1_provided_comm_worked || snmpv2c_provided_comm_worked ) ) {
    set_kb_item( name:"login/SNMP/success", value:TRUE );
    set_kb_item( name:"login/SNMP/success/port", value:port );
    register_host_detail( name:"Auth-SNMP-Success", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp" );
  }

  if( SNMP_v1 || SNMP_v2c || SNMP_v3 ) {

    do_logging = TRUE;

    if( SNMP_v3 ) {
      # correct provided credentials
      if( ! snmp_error ) {
        additional_info_report += '- SNMPv3: It was possible to log using the credentials provided via the target configuration or via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076).\n';
        set_kb_item( name:"login/SNMP/success", value:TRUE );
        set_kb_item( name:"login/SNMP/success/port", value:port );
        register_host_detail( name:"Auth-SNMP-Success", value:"Protocol SNMPv3, Port " + port + "/udp" );
      } else {
        # wrong provided credentials
        if( v3_creds ) {
          additional_info_report += '- SNMPv3: It was NOT possible to log in using the credentials provided via the target configuration or via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076)". Error: ' + snmp_error + '\n';
          set_kb_item( name:"login/SNMP/failed", value:TRUE );
          set_kb_item( name:"login/SNMP/failed/port", value:port );
          register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv3, Port " + port + "/udp : Login failure" );
        } else {
          additional_info_report += '- SNMPv3: It was possible to determine that a service is running by using random credentials and based on the following response: ' + snmp_error + '\n';
        }
      }
    }

    report += 'An SNMP server is running on this host.\n\nThe following SNMP versions are supported:\n';
    if( SNMP_v1 )  report += '- SNMPv1\n';
    if( SNMP_v2c ) report += '- SNMPv2c\n';
    if( SNMP_v3 )  report += '- SNMPv3\n';

    service_register( port:port, ipproto:"udp", proto:"snmp" );
    set_kb_item( name:"SNMP/detected", value:TRUE );
  }

  # nb: Other cases for SNMPv3 / from invalid_snmpv3_creds_errors which have been not covered previously
  if( v3_creds && ! SNMP_v3 && in_array( array:invalid_snmpv3_creds_errors, search:snmp_error ) ) {

    additional_info_report += '- SNMPv3: Wrong set of credentials provided via the target configuration or via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076)". Error: ' + snmp_error + '\n';
    if( "generate_Ku: Error" >< snmp_error )
      additional_info_report += '- Note: "SNMPv3 Password" and/or "SNMPv3 Privacy Password" given via "SNMP Authorization (OID: 1.3.6.1.4.1.25623.1.0.105076)" is too short (should be >= 8 chars)\n';

    set_kb_item( name:"login/SNMP/failed", value:TRUE );
    set_kb_item( name:"login/SNMP/failed/port", value:port );
    register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv3, Port " + port + "/udp : Wrong set of SNMPv3 credentials given" );

    do_logging = TRUE;
  }

  if( do_logging ) {

    # nb: In case of wrongly given credentials and no SNMP detection at all
    if( ! report )
      report = 'It was NOT possible to determine if a SNMP server is running on this host.\n';

    if( additional_info_report )
      report += '\nAdditional info:\n' + additional_info_report;

    log_message( port:port, proto:"udp", data:chomp( report ) );
  }

  exit( 0 );
}

# nb: This is just a fallback to detect SNMP, however none of the SNMP functions from snmp_func.inc
# will work as they rely on snmpv3_get() as well.
else {

  #nb: Don't use UDP/PORTS or snmp_get_port() as the check below is quite unreliable against other non-snmp UDP services
  port = 161;

  communities = _create_community_list( port:port );

  if( ! get_udp_port_state( port ) ) {

    # nb: Only do the logging of failed auth if the user has provided credentials.
    if( provided_community && strlen( provided_community ) > 0 ) {
      set_kb_item( name:"login/SNMP/failed", value:TRUE );
      set_kb_item( name:"login/SNMP/failed/port", value:port );
      register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp : No port open" );
    }

    exit( 0 );
  }

  socudp161 = open_sock_udp( port );

  data = 'An SNMP server is running on this host.\n\nThe following SNMP versions are supported:\n';
  flag = 0;

  ver[0] = "1";
  ver[1] = "2c";
  ver[2] = "2u";

  if( socudp161 ) {

    foreach community( keys( communities ) ) {

      SNMP_BASE = 31;
      COMMUNITY_SIZE = strlen( community );

      sz = COMMUNITY_SIZE % 256;

      len = SNMP_BASE + COMMUNITY_SIZE;
      len_hi = len / 256;
      len_lo = len % 256;

      for( i = 0; i < 3; i++ ) {

        req = raw_string( 0x30, 0x82, len_hi, len_lo,
                          0x02, 0x01, i, 0x04,
                          sz );

        req = req + community +
              raw_string( 0xA1,0x18, 0x02,
                   0x01, 0x01, 0x02, 0x01,
                   0x00, 0x02, 0x01, 0x00,
                   0x30, 0x0D, 0x30, 0x82,
                   0x00, 0x09, 0x06, 0x05,
                   0x2B, 0x06, 0x01, 0x02,
                   0x01, 0x05, 0x00 );
        send( socket:socudp161, data:req );

        result = recv( socket:socudp161, length:1000, timeout:1 );
        if( result ) {
          flag++;
          if( ver[i] == "1" && ! v1_detected ) {
            v1_detected = TRUE;
            data += string( "SNMPv", ver[i], "\n" );
            set_kb_item( name:"SNMP/" + port + "/v1/working", value:TRUE );
            set_kb_item( name:"SNMP/" + port + "/working", value:TRUE );
            replace_kb_item( name:"SNMP/" + port + "/preferred_version", value:1 );
          } else if( ver[i] == "2c" && ! v2c_detected ) {
            v2c_detected = TRUE;
            data += string( "SNMPv", ver[i], "\n" );
            set_kb_item( name:"SNMP/" + port + "/v2c/working", value:TRUE );
            set_kb_item( name:"SNMP/" + port + "/working", value:TRUE );
            replace_kb_item( name:"SNMP/" + port + "/preferred_version", value:2 );
          } else if( ver[i] == "2u" && ! v2u_detected ) {
            v2u_detected = TRUE;
            data += string( "- SNMPv", ver[i], "\n" );
          }

          if( ver[i] == "1" ) {
            set_kb_item( name:"SNMP/" + port + "/v1/community", value:community );
            if( community == provided_community )
              snmpv1_provided_comm_worked = TRUE;
          }

          if( ver[i] == "2c" ) {
            set_kb_item( name:"SNMP/" + port + "/v2c/community", value:community );
            if( community == provided_community )
              snmpv2c_provided_comm_worked = TRUE;
          }
        }
      }
    }

    if( flag > 0 ) {
      log_message( port:port, data:data, protocol:"udp" );
      service_register( port:port, ipproto:"udp", proto:"snmp" );
      set_kb_item( name:"SNMP/detected", value:TRUE );
    }
    close( socudp161 ); # end if (socudp161)

    if( ! snmpv1_provided_comm_worked && ! snmpv2c_provided_comm_worked && provided_community && strlen( provided_community ) > 0 ) {
      set_kb_item( name:"login/SNMP/failed", value:TRUE );
      set_kb_item( name:"login/SNMP/failed/port", value:port );
      register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp, Community " + provided_community + " : Login failure" );
    } else if( provided_community && strlen( provided_community ) > 0 && ( snmpv1_provided_comm_worked || snmpv2c_provided_comm_worked ) ) {
      set_kb_item( name:"login/SNMP/success", value:TRUE );
      set_kb_item( name:"login/SNMP/success/port", value:port );
      register_host_detail( name:"Auth-SNMP-Success", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp" );
    }
  } else if( provided_community && strlen( provided_community ) > 0 ) {
    set_kb_item( name:"login/SNMP/failed", value:TRUE );
    set_kb_item( name:"login/SNMP/failed/port", value:port );
    register_host_detail( name:"Auth-SNMP-Failure", value:"Protocol SNMPv1/SNMPv2c, Port " + port + "/udp : Failed to connect to port" );
  }

  port = 162;
  socudp162 = open_sock_udp( port );
  if( socudp162 ) {
    send( socket:socudp162, data:string( "\r\n" ) );
    result = recv( socket:socudp162, length:1, timeout:1 );
    if( strlen( result ) > 1 ) {
      data = "SNMP Trap Agent port open, it is possible to overflow the SNMP Traps log with fake traps (if proper community names are known), causing a Denial of Service";
      log_message( port:port, data:data, protocol:"udp" );
    }
  }
  close( socudp162 );
}

exit( 0 );
