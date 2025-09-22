# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103118");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: SMTP 'STARTTLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"summary", value:"Checks if the remote SMTP server supports SSL/TLS with the
  'STARTTLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc3207");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );

if( get_port_transport( port ) > ENCAPS_IP )
  exit( 0 );

helo = smtp_get_helo_from_kb( port:port );
if( ! soc = smtp_open( port:port, data:helo, send_ehlo:TRUE ) )
  exit( 0 );

send( socket:soc, data:string( "STARTTLS\r\n" ) );
r = smtp_recv_line( socket:soc );
if( ! r ) {
  smtp_close( socket:soc, check_data:r );
  exit( 0 );
}

if( r =~ "^220[ -]" || "Ready to start TLS" >< r || "TLS go ahead" >< r || " Start TLS" >< r ) {

  set_kb_item( name:"smtp/starttls/supported", value:TRUE );
  set_kb_item( name:"smtp/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"smtp" );

  report = "The remote SMTP server supports SSL/TLS with the 'STARTTLS' command.";

  commandlist = get_kb_list( "smtp/fingerprints/" + port + "/nontls_commandlist" );
  if( commandlist && typeof( commandlist ) == "array" ) {
    commandlist = sort( commandlist );
    command_report = "";
    foreach command( commandlist ) {
      if( ! command_report )
        command_report = command;
      else
        command_report += ", " + command;
    }
    if( command_report )
      report = string( report, "\n\nThe remote SMTP server is announcing the following available ESMTP commands (EHLO response) before sending the 'STARTTLS' command:\n\n", command_report );
  }

  # nb: socket_negotiate_ssl() would fork on multiple hostnames causing issues with failed connections
  # / socket communication so we're directly disable the use of SNI (and the forking) on this port.
  set_kb_item( name:"Host/SNI/" + port + "/force_disable", value:1 );

  # nb: socket_negotiate_ssl() is "upgrading" the socket and the socket number stays the same if
  # successful so we only need to check it like this. Furthermore if no SSL/TLS connection could
  # be estabilshed socket_negotiate_ssl() will close the passed socket internally so we don't need
  # to close it outside of this if block.
  if( socket_negotiate_ssl( socket:soc ) ) {

    send( socket:soc, data:'EHLO ' + helo + '\r\n' );
    ehlo = smtp_recv_line( socket:soc, code:"250" );
    smtp_close( socket:soc, check_data:ehlo );

    if( ehlo ) {

      commands = split( ehlo, keep:FALSE );
      first = 0;
      foreach command( commands ) {

        # nb: The first command includes the remote hostname so we're ignoring it here.
        first++;
        if( first == 1 )
          continue;

        _command = eregmatch( string:command, pattern:"^250[ -](.+)" );
        if( _command[1] ) {
          # nb: Don't set "smtp/fingerprints/" + port + "/nontls_commandlist" which is already collected by smtp_get_banner() via smtpserver_detect.nasl.
          set_kb_item( name:"smtp/fingerprints/" + port + "/tls_commandlist", value:_command[1] );
        }
      }

      if( auth_string = egrep( string:ehlo, pattern:"^250[ -]AUTH .+" ) ) {

        set_kb_item( name:"smtp/auth_methods/available", value:TRUE );

        auth_string = chomp( auth_string );
        auth_string = substr( auth_string, 9 );
        auth_report = "";
        auths = split( auth_string, sep:" ", keep:FALSE );

        foreach auth( auths )
          set_kb_item( name:"smtp/fingerprints/" + port + "/tls_authlist", value:auth );
      }
    }

    # nb: Don't close the socket here, see note above.
  }

  # nb: We're getting the list here again to be able to sort it afterwards for easier comparison with the previous list.
  commandlist = get_kb_list( "smtp/fingerprints/" + port + "/tls_commandlist" );
  if( commandlist && typeof( commandlist ) == "array" ) {
    commandlist = sort( commandlist );
    command_report = "";
    foreach command( commandlist ) {
      if( ! command_report )
        command_report = command;
      else
        command_report += ", " + command;
    }
  }
  if( command_report )
    report = string( report, "\n\nThe remote SMTP server is announcing the following available ESMTP commands (EHLO response) after sending the 'STARTTLS' command:\n\n", command_report );

  log_message( port:port, data:report );
} else {
  smtp_close( socket:soc, check_data:r );
  set_kb_item( name:"smtp/starttls/not_supported", value:TRUE );
  set_kb_item( name:"smtp/starttls/not_supported/port", value:port );
}

exit( 0 );
