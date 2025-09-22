# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10263");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"This detects the SMTP Server's type and version by connecting to
  the server and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");

ports = smtp_get_ports();
foreach port( ports ) {

  # nb: Don't detect a LMTP service as SMTP. This normally only happens if a LMTP service is bound
  # to a SMTP port (checked by this VT by default) but we're checking it just to be sure...
  if( service_verify( port:port, proto:"lmtp" ) )
    continue;

  # nb: smtp_get_banner is verifying that we're receiving an expected SMTP response so its
  # safe to use a register_service below.
  banner = smtp_get_banner( port:port );
  if( ! banner )
    continue;

  guess    = NULL;
  commands = NULL;

  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"smtp", message:"A SMTP Server seems to be running on this port." );

  set_kb_item( name:"smtp/banner/available", value:TRUE );
  set_kb_item( name:"pop3_imap_or_smtp/banner/available", value:TRUE );

  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
  if( get_port_transport( port ) > ENCAPS_IP ) {
    ehlo = get_kb_item( "smtp/fingerprints/" + port + "/tls_ehlo_banner" );
    is_tls = TRUE;
  } else {
    ehlo = get_kb_item( "smtp/fingerprints/" + port + "/nontls_ehlo_banner" );
    is_tls = FALSE;
  }

  if( "qmail" >< banner || "qmail" >< help ) {
    set_kb_item( name:"smtp/qmail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qmail/detected", value:TRUE );
    guess += '\n- Qmail';
  }

  if( "XMail " >< banner ) {
    set_kb_item( name:"smtp/xmail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/xmail/detected", value:TRUE );
    guess += '\n- XMail';
  }

  if( egrep( pattern:".*nbx.*Service ready.*", string:banner ) ) {
    set_kb_item( name:"smtp/3comnbx/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/3comnbx/detected", value:TRUE );
    guess += '\n- 3comnbx';
  }

  if( "ZMailer Server" >< banner ||
      ( "This mail-server is at Yoyodyne Propulsion Inc." >< help && # Default help text.
        "Out" >< quit && "zmhacks@nic.funet.fi" >< help ) ) {
    set_kb_item( name:"smtp/zmailer/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/zmailer/detected", value:TRUE );
    str = egrep( pattern:" ZMailer ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1" );
      guess += '\n- ZMailer version ' + str;
    } else {
      guess += '\n- ZMailer';
    }
  }

  if( "CheckPoint FireWall-1" >< banner ) {
    set_kb_item( name:"smtp/firewall-1/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/firewall-1/detected", value:TRUE );
    guess += '\n- CheckPoint FireWall-1';
  }

  if( "InterMail" >< banner ||
      ( "This SMTP server is a part of the InterMail E-mail system" >< help &&
        "Ok resetting state." >< rset && "ESMTP server closing connection." >< quit ) ) {
    set_kb_item( name:"smtp/intermail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/intermail/detected", value:TRUE );
    str = egrep( pattern:"InterMail ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1" );
      guess += '\n- InterMail version ' + str;
    } else {
      guess += '\n- InterMail';
    }
  }

  if( "mail rejector" >< banner ||
      ( ehlo && match( pattern:"*snubby*", string:ehlo, icase:TRUE ) ) ) {
    set_kb_item( name:"smtp/snubby/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/snubby/detected", value:TRUE );
    smtp_set_is_marked_wrapped( port:port );
    guess  += '\n- Snubby Mail Rejector (not a real SMTP server)';
    report  = "Verisign mail rejector appears to be running on this port. You probably mistyped your hostname and the scanner is scanning the wildcard address in the .COM or .NET domain.";
    report += '\n\nSolution: enter a correct hostname';
    log_message( port:port, data:report );
  }

  if( egrep( pattern:"Mail(Enable| Enable SMTP) Service", string:banner ) ) {
    set_kb_item( name:"smtp/mailenable/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mailenable/detected", value:TRUE );
    guess += '\n- MailEnable SMTP';
  }

  if( " MDaemon " >< banner ) {
    set_kb_item( name:"smtp/mdaemon/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mdaemon/detected", value:TRUE );
    guess += '\n- MDaemon SMTP';
  }

  if( " InetServer " >< banner ) {
    set_kb_item( name:"smtp/inetserver/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/inetserver/detected", value:TRUE );
    guess += '\n- A-V Tronics InetServ SMTP';
  }

  if( "Quick 'n Easy Mail Server" >< banner ) {
    set_kb_item( name:"smtp/quickneasy/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/quickneasy/detected", value:TRUE );
    guess += '\n' + "- Quick 'n Easy Mail Server";
  }

  if( "QK SMTP Server" >< banner ) {
    set_kb_item( name:"smtp/qk_smtp/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qk_smtp/detected", value:TRUE );
    guess += '\n- QK SMTP Server';
  }

  if( "ESMTP CommuniGate Pro" >< banner ) {
    set_kb_item( name:"smtp/communigate/pro/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/communigate/pro/detected", value:TRUE );
    guess += '\n- CommuniGate Pro';
  }

  if( "TABS Mail Server" >< banner ) {
    set_kb_item( name:"smtp/tabs/mailcarrier/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/tabs/mailcarrier/detected", value:TRUE );
    guess += '\n- TABS MailCarrier';
  }

  if( "ESMTPSA" >< banner ) {
    set_kb_item( name:"smtp/esmtpsa/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/esmtpsa/detected", value:TRUE );
    guess += '\n- Various Mail Server like Rumble SMTP';
  }

  if( banner =~ "^220.*SonicWall " ) {
    set_kb_item( name:"smtp/sonicwall/email_security/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/sonicwall/email_security/detected", value:TRUE );
    guess += '\n- SonicWall Email Security SMTP';
  }

  if( banner =~ "^220 [^ ]+ ESMTP$" || "Powered by the new deepOfix Mail Server" >< banner || "Welcome to deepOfix" >< banner || "qmail" >< help ) {
    set_kb_item( name:"smtp/deepofix/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/deepofix/detected", value:TRUE );
    guess += '\n- deepOfix';
  }

  if( banner =~ "FirstClass [A-Z]?SMTP" ) {
    set_kb_item( name:"smtp/opentext/firstclass/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/opentext/firstclass/detected", value:TRUE );
    guess += '\n- OpenText FirstClass';
  }

  if( banner =~ "ESMTP Xpressions" ) {
    set_kb_item( name:"smtp/unify/xpressions/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/unify/xpressions/detected", value:TRUE );
    guess += '\n- Unify OpenScape Xpressions';
  }

  if( banner =~ "ArgoSoft Mail Server" ) {
    set_kb_item( name:"smtp/argosoft/mailserver/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/argosoft/mailserver/detected", value:TRUE );
    guess += '\n- ArgoSoft Mail Server';
  }

  if( banner =~ "(HCL|IBM|Lotus) Domino" ) {
    set_kb_item( name:"smtp/hcl/domino/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/hcl/domino/detected", value:TRUE );
    guess += '\n- HCL | IBM | Lotus Domino';
  }

  if( banner =~ "IceWarp" ) {
    set_kb_item( name:"smtp/icewarp/mailserver/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/icewarp/mailserver/detected", value:TRUE );
    guess += '\n- IceWarp Mail Server';
  }

  if( banner == "220 ESMTP IMSVA" ) {
    set_kb_item( name:"smtp/trend_micro/imsva/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/trend_micro/imsva/detected", value:TRUE );
    guess += '\n- Trend Micro Interscan Messaging Security Virtual Appliance (IMSVA)';
  }

  if( banner =~ "220.*[ (]JAMES .*SMTP .*Server" ) {
    set_kb_item( name:"smtp/apache/james_server/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/apache/james_server/detected", value:TRUE );
    guess += '\n- Apache James Server';
  }

  # 220 example.com SurgeSMTP (Version 7.1f-15) http://surgemail.com
  # 220 SMTP example.com (Surgemail Version 3.7b6-6)
  if( banner =~ "Surge(mail|SMTP)" ) {
    set_kb_item( name:"smtp/surgemail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/surgemail/detected", value:TRUE );
    guess += '\n- SurgeMail Server';
  }

  if( banner =~ "220.* GroupWise Internet Agent" ) {
    set_kb_item( name:"smtp/groupwise/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/groupwise/detected", value:TRUE );
    guess += '\n- Micro Focus / Novell GroupWise';
  }

  # 220 barracuda.test.local ESMTP (09678d23bc13369ca0f4a4c15ae7f1d4)
  if( banner =~ "220 [^ ]+ ESMTP \([[a-fA-F0-9]{32}\)" ) {
    set_kb_item( name:"smtp/barracuda/email_security_gateway/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/barracuda/email_security_gateway/detected", value:TRUE );
    guess += '\n- Barracuda Email Security Gateway';
  }

  # 220 mail.example.com ESMTP Sophos Email Appliance v4.5.3.6
  # 220 mail.example.com ESMTP Example Sophos Email Appliance v4.4.1.1
  if( banner =~ "220.* Sophos Email Appliance" ) {
    set_kb_item( name:"smtp/sophos/email_appliance/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/sophos/email_appliance/detected", value:TRUE );
    guess += '\n- Sophos Email Appliance';
  }

  # 220 mail.example.com ESMTP Symantec Messaging Gateway
  if( banner =~ "220.* ESMTP Symantec Messaging Gateway" ) {
    set_kb_item( name:"smtp/symantec/smg/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/symantec/smg/detected", value:TRUE );
    guess += '\n- Symantec Messaging Gateway';
  }

  # 220-mailcow ESMTP Postcow
  if( banner =~ "220.* ESMTP Postcow" ) {
    set_kb_item( name:"smtp/mailcow/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mailcow/detected", value:TRUE );
    guess += '\n- Mailcow';
  }

  # 220 mail.example.com ESMTP OpenSMTPD
  if( banner =~ "220.* ESMTP OpenSMTPD" ) {
    set_kb_item( name:"smtp/opensmtpd/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/opensmtpd/detected", value:TRUE );
    guess += '\n- OpenSMTPD';
  }

  report = 'Remote SMTP server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably:\n' + guess;

  if( is_tls )
    commandlist = get_kb_list( "smtp/fingerprints/" + port + "/tls_commandlist" );
  else
    commandlist = get_kb_list( "smtp/fingerprints/" + port + "/nontls_commandlist" );

  if( commandlist && is_array( commandlist ) ) {
    # Sort to not report changes on delta reports if just the order is different
    commandlist = sort( commandlist );
    foreach command( commandlist ) {
      if( ! commands )
        commands = command;
      else
        commands += ", " + command;
    }
  }

  if( strlen( commands ) > 0 ) {
    ehlo_report = '\n\nThe remote SMTP server is announcing the following available ESMTP commands (EHLO response) via an ';
    if( is_tls )
      ehlo_report += "encrypted";
    else
      ehlo_report += "unencrypted";
    report += ehlo_report += ' connection:\n\n' + commands;
  }

  log_message( port:port, data:report );
}

exit( 0 );
