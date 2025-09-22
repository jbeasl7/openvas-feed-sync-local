# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105839");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-08-01 09:40:35 +0200 (Mon, 01 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RMI Registry Service Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1099);

  script_tag(name:"summary", value:"Detection of a Remote Method Invocation (RMI) registry
  service.");

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");
include("rmi_func.inc");

port = unknownservice_get_port( default:1099 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

if( ! rmi_connect( socket:soc ) ) {
  close( soc );
  exit( 0 );
}

set_kb_item( name:"rmi_registry/detected", value:TRUE );

service_register( port:port, proto:"rmi_registry" );

res = rmi_list( socket:soc );

close( soc );

extra = "";

if( "java.lang.String" >< res && "java..io.IOException" >!< res ) {
  buf = split( res, sep:"java.lang.String", keep:FALSE );
  if( max_index( buf ) == 2 ) {
    buf = buf[1];
    index = stridx( buf, "t" ); # Seems to be the delimiter
    if( index > 0 ) {
      max_count = 10;
      count = 0;

      for( i = index; i < strlen( buf ); i++ ) {
        if( count >= max_count ) { # nb: We just enumerate maximum 10 objects
          if( extra != "" )
            extra += "... (truncated to maximum 10 objects but there might be more)";
          break;
        }
        count++;

        # nb: We need to open a new socket every time we request something
        if( ! soc = open_sock_tcp( port ) )
          break;

        if( ! rmi_connect( socket:soc ) ) {
          close( soc );
          break;
        }

        len = getword( blob:buf, pos:i + 1 );
        name = substr( buf, i + 3, i + 2 + len );

        res = rmi_lookup( socket:soc, obj_name:name );
        close( soc );

        if( "UnicastRef" >< res && "java.rmi.server" >< res) {
          data = split( res, sep:"UnicastRef", keep:FALSE );
          if( max_index( data ) == 2 ) {
            data = data[1];
            # Adjust if UnicastRef2
            if( data[0] == 2 )
              data = substr( data, 2 );
            host_len = getword( blob:data, pos:0 );
            rmi_host = substr( data, 2, host_len + 1 );
            rmi_port = getword( blob:data, pos:host_len + 4 );
            rmi_obj_id = substr( data, host_len + 6, host_len + 27);

            extra += "rmi://" + rmi_host + ":" + rmi_port + "/" + name + '\n';
            set_kb_item( name:"rmi_registry/" + port + "/registry_objects",
                         value:rmi_host + ":" + rmi_port + ":" + name + ":" + hexstr( rmi_obj_id ) );
          }
        }

        i += len + 2;
      }
    }
  }
}

report = "A RMI registry service is running at this port.";

if( extra != "" )
  report += '\n\nThe following remote registry objects have been extracted:\n\n' + chomp( extra );

log_message( port:port, data:report );

exit( 0 );
