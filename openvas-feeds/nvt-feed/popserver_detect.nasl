# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10185");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("POP3 Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/pop3", 110, 995);

  script_tag(name:"summary", value:"This detects the POP3 Server's type and version by connecting to
  the server and processing the received banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("list_array_func.inc");
include("pop3_func.inc");
include("port_service_func.inc");

ports = pop3_get_ports();
foreach port( ports ) {

  # nb: pop3_get_banner() is verifying (via pop3_verify_banner) that we have
  # received a POP3 banner here so it is safe to register the service below.
  banner = pop3_get_banner( port:port );
  if( ! banner )
    continue;

  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"pop3", message:"A POP3 Server seems to be running on this port." );

  guess = NULL;
  capas = NULL;

  if( get_port_transport( port ) > ENCAPS_IP )
    is_tls = TRUE;
  else
    is_tls = FALSE;

  set_kb_item( name:"pop3/banner/available", value:TRUE );
  set_kb_item( name:"pop3_imap_or_smtp/banner/available", value:TRUE );

  impl_banner = get_kb_item( "pop3/fingerprints/" + port + "/impl_banner" );

  # +OK Dovecot ready.
  # +OK Dovecot (Debian) ready.
  if( "Dovecot " >< banner && " ready" >< banner ) {
    set_kb_item( name:"imap_or_pop3/dovecot/detected", value:TRUE );
    set_kb_item( name:"pop3/dovecot/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/dovecot/detected", value:TRUE );
    guess += '\n- Dovecot';
  }

  if( "POP3 on InetServer" >< banner ) {
    set_kb_item( name:"pop3/avtronics/inetserv/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/avtronics/inetserv/detected", value:TRUE );
    guess += '\n- A-V Tronics InetServ';
  }

  if( "Qpopper" >< banner ) {
    set_kb_item( name:"pop3/qpopper/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/qpopper/detected", value:TRUE );
    guess += '\n- QPopper';
  }

  if( "POP3" >< banner && "MDaemon" >< banner ) {
    set_kb_item( name:"pop3/mdaemon/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/mdaemon/detected", value:TRUE );
    guess += '\n- MDaemon';
  }

  if( "Proxy-POP server (Delegate" >< banner ) {
    set_kb_item( name:"pop3/delegate/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/delegate/detected", value:TRUE );
    guess += '\n- Delegate';
  }

  if( banner =~ "Argosoft Mail Server" ) {
    set_kb_item( name:"pop3/argosoft/mailserver/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/argosoft/mailserver/detected", value:TRUE);
    guess += '\n- Argosoft Mail Server';
  }

  if( banner =~ "(HCL|Lotus|IBM) Notes POP3 Server" ) {
    set_kb_item( name:"pop3/hcl/domino/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/hcl/domino/detected", value:TRUE);
    guess += '\n- HCL | IBM | Lotus Notes';
  }

  if( banner =~ "IceWarp" ) {
    set_kb_item( name:"pop3/icewarp/mailserver/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/icewarp/mailserver/detected", value:TRUE );
    guess += '\n- IceWarp Mail Server';
  }

  if( banner =~ "\(JAMES POP3 Server.+ready" ) {
    set_kb_item( name:"pop3/apache/james_server/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/apache/james_server/detected", value:TRUE );
    guess += '\n- Apache James Server';
  }

  if( "Zimbra POP3 server ready" >< banner || "IMPLEMENTATION ZimbraInc" >< impl_banner ) {
    set_kb_item( name:"pop3/zimbra/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/zimbra/detected", value:TRUE );
    guess += '\n- Zimbra';
  }

  if( "GroupWise POP3 server ready" >< banner ) {
    set_kb_item( name:"pop3/groupwise/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/groupwise/detected", value:TRUE );
    guess += '\n- Micro Focus / Novel GroupWise';
  }

  if( "MailEnable POP3 Server" >< banner ) {
    set_kb_item( name:"pop3/mailenable/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/mailenable/detected", value:TRUE );
    guess += '\n- MailEnable';
  }

  if( is_tls )
    capalist = get_kb_list( "pop3/fingerprints/" + port + "/tls_capalist" );
  else
    capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );

  if( egrep( pattern:"surgemail", string:banner, icase:TRUE ) ||
      ( capalist && in_array( search:"surgemail", array:capalist, icase:TRUE ) ) ) {
    set_kb_item( name:"pop3/surgemail/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/surgemail/detected", value:TRUE );
    guess += '\n- SurgeMail Server';
  }

  report = 'Remote POP3 server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably:\n' + guess;

  if( capalist && is_array( capalist ) ) {
    # Sort to not report changes on delta reports if just the order is different
    capalist = sort( capalist );
    foreach capa( capalist ) {
      if( ! capas )
        capas = capa;
      else
        capas += ", " + capa;
    }
  }

  if( strlen( capas ) > 0 ) {
    capa_report = '\n\nThe remote POP3 server is announcing the following available CAPABILITIES via an ';
    if( is_tls )
      capa_report += "encrypted";
    else
      capa_report += "unencrypted";
    report += capa_report += ' connection:\n\n' + capas;
  }

  log_message( port:port, data:report );
}

exit( 0 );
