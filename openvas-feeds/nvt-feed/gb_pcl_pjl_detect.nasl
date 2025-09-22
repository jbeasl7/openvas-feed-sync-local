# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108641");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-09-10 11:01:30 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Printer Job Language (PJL) / Printer Command Language (PCL) Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("find_service.nasl", "dont_print_on_printers.nasl");
  script_require_ports("Services/hp-pjl", 2000, 2501, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9112, 9113, 9114, 9115, 9116, 10001);

  script_xref(name:"URL", value:"http://www.maths.usyd.edu.au/u/psz/ps.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130416193817/http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568");
  script_xref(name:"URL", value:"http://h10032.www1.hp.com/ctg/Manual/bpl13208.pdf");
  script_xref(name:"URL", value:"http://h10032.www1.hp.com/ctg/Manual/bpl13207.pdf");
  script_xref(name:"URL", value:"https://developers.hp.com/system/files/PJL_Technical_Reference_Manual.pdf");
  script_xref(name:"URL", value:"https://web.archive.org/web/20151122184353/http://download.brother.com/welcome/doc002907/Tech_Manual_Y.pdf");

  script_tag(name:"summary", value:"The remote service supports the Printer Job Language (PJL)
  and/or Printer Command Language (PCL) protocol and answered to a PJL and/or PCL request.

  This indicates the remote device is probably a printer running JetDirect.

  Through PJL/PCL, users can submit printing jobs, transfer files to or from the printers, change
  some settings, etc.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("list_array_func.inc");
include("network_func.inc");
include("pcl_pjl.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("string_hex_func.inc");

default_ports = pcl_pjl_get_default_ports();
ports = service_get_ports( proto:"hp-pjl", default_port_list:default_ports );

vt_strings  = get_vt_strings();
final_ports = make_array();
reqs        = pcl_pjl_get_detect_requests( vt_strings:vt_strings );

# This makes sure to add the default ports even if dont_print_on_printers.nasl failed to register the service as hp-pjl.
foreach default_port( default_ports ) {
  if( ! in_array( search:default_port, array:ports, part_match:FALSE ) &&
      get_port_state( default_port ) ) {
    ports = make_list( ports, default_port );
  }
}

# This is used later to know if the port is already registered in the KB as hp-pjl.
foreach port( ports ) {
  if( service_verify( port:port, proto:"hp-pjl" ) )
    final_ports[port] = TRUE;
  else
    final_ports[port] = FALSE;
}

foreach final_port( keys( final_ports ) ) {

  port  = final_port;
  in_kb = final_ports[final_port];

  if( ! in_kb && service_is_known( port:port ) )
    continue;

  # PJL/PCL ports get the Hex banner set to "aeaeaeaeae" in pcl_pjl_register_all_ports() called by dont_print_on_printers.nasl
  if( hexstr( unknown_banner_get( port:port, dontfetch:TRUE ) ) == "aeaeaeaeae" || ! in_kb ) {

    s = open_sock_tcp( port );
    if( ! s )
      continue;

    identified = FALSE;
    report = "";
    final_report = "";
    pjl_support = FALSE;
    pcl_support = FALSE;

    foreach req( keys( reqs ) ) {

      response_check = reqs[req];

      send( socket:s, data:req );
      r = recv( socket:s, length:1024 );
      if( ! r )
        continue;

      if( "@PJL" >< r && response_check >< r )
        pjl_support = TRUE;

      if( "PCL" >< r && response_check >< r )
        pcl_support = TRUE;

      if( '@PJL INFO ID\r\n' >< r ) {

        identified = TRUE;

        lines = split( r, keep:FALSE );
        if( max_index( lines ) >= 1 && strlen( lines[1] ) > 0 ) {

          info = ereg_replace( string:lines[1], pattern:'^ *"(.*)" *$', replace: "\1" );
          if( strlen( info ) == 0 )
            info = lines[1];

          if( ! info )
            continue;

          if( report )
            report += '\n';
          report = strcat( report, 'The device INFO ID is:\n', info );
          set_kb_item( name:"hp-pjl/banner/available", value:TRUE );
          set_kb_item( name:"hp-pjl/" + port + "/banner", value:chomp( info ) );
        }
      } else if( '@PJL INFO PRODINFO\r\n' >< r ) {

        identified = TRUE;

        # HWAddress = 48:E2:44:43:EC:C3
        mac = verify_register_mac_address( data:r, desc:"Printer Job Language (PJL) / Printer Command Language (PCL) Detection", prefix_string:"HWAddress = " );
        if( mac ) {
          if( report )
            report += '\n';
          report = strcat( report, 'The device MAC Address is:\n', mac );
        }

        if( "?" >!< r ) {
          lines = split( r, keep:FALSE );
          if( max_index( lines ) >= 1 ) {

            foreach line( lines ) {
              line = chomp( line );
              if( ! line || line == "@PJL INFO PRODINFO" )
                continue;

              set_kb_item( name:"hp-pjl/" + port + "/prodinfo", value:line );
            }
          }
        }
      } else if( '@PJL INFO STATUS\r\n' >< r || '@PJL USTATUS DEVICE\r\n' ) {

        identified = TRUE;

        if( "?" >!< r ) {
          lines = split( r, keep:FALSE );
          if( max_index( lines ) >= 1 ) {

            foreach line( lines ) {
              line = chomp( line );
              if( ! line ||
                  line == "@PJL INFO STATUS" || line == "@PJL USTATUS DEVICE" || # nb: Standard responses
                  line == '\f@PJL INFO STATUS' || line == '\f@PJL USTATUS DEVICE' ) # nb: Some responded with a 0x0c in front of the returned command.
                continue;

              set_kb_item( name:"hp-pjl/" + port + "/status", value:line );
            }
          }
        }
      } else if( response_check >< r ) {
        identified = TRUE;
      }
    }

    close( s );

    if( identified ) {

      # Used in gb_ipp_detect.nasl as a "script_mandatory_keys()" as we don't want to run that VT
      # against every web server and just against the ones on systems which *might* support IPP.
      set_kb_item( name:"Host/could_support_ipp", value:TRUE );

      if( pjl_support || pcl_support )
        final_report = "The device supports: ";

      if( pjl_support ) {
        final_report += "PJL";
        set_kb_item( name:"hp-pjl/port", value:port );
      }

      if( pcl_support ) {
        if( pjl_support )
          final_report += ", ";
        final_report += "PCL";
        set_kb_item( name:"hp-pcl/port", value:port );
      }

      if( final_report && report )
        report = final_report += '\n' + report;
      else if( final_report )
        report = final_report;

      log_message( port:port, data:report );

      if( ! in_kb ) {

        if( pjl_support )
          service_register( port:port, proto:"hp-pjl" );

        if( pcl_support )
          service_register( port:port, proto:"hp-pcl" );

        pcl_pjl_register_all_ports();
      }
    }
  }
}

exit( 0 );
