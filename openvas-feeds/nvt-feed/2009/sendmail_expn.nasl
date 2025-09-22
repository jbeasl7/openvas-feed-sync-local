# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100072");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Check if Mailserver answer to VRFY and EXPN requests");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"http://cr.yp.to/smtp/vrfy.html");

  script_tag(name:"solution", value:"Disable VRFY and/or EXPN on your Mailserver.

  For postfix add 'disable_vrfy_command=yes' in 'main.cf'.

  For Sendmail add the option 'O PrivacyOptions=goaway'.

  It is suggested that, if you really want to publish this type of information, you use a mechanism
  that legitimate users actually know about, such as Finger or HTTP.");

  script_tag(name:"summary", value:"The Mailserver on this host answers to VRFY and/or EXPN requests.");

  script_tag(name:"insight", value:"VRFY and EXPN ask the server for information about an address. They are
  inherently unusable through firewalls, gateways, mail exchangers for part-time hosts, etc.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );

# nb: Don't use smtp_open as we want to grab the different responses below.
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

bannertxt = smtp_recv_banner( socket:soc );
if( ! bannertxt ) {
  smtp_close( socket:soc, check_data:bannertxt );
  exit( 0 );
}

send( socket:soc, data:string( "EHLO ", smtp_get_helo_from_kb( port:port ), "\r\n" ) );
ehlotxt = smtp_recv_line( socket:soc, code:"(250|550)" );
if( ! ehlotxt ) {
  smtp_close( socket:soc, check_data:ehlotxt );
  exit( 0 );
}

send( socket:soc, data:string( "VRFY root\r\n" ) );
vrfy_txt = smtp_recv_line( socket:soc, code:"(25[0-2]|550)" );

if( vrfy_txt ) {
  if( "Administrative prohibition" >!< vrfy_txt &&
      "Access Denied" >!< vrfy_txt &&
      "not available" >!< vrfy_txt &&
      "String does not match anything" >!< vrfy_txt &&
      "Cannot VRFY user" >!< vrfy_txt &&
      "VRFY disabled" >!< vrfy_txt &&
      "252 send some mail, i'll try my best" >!< vrfy_txt ) {
    vtstrings = get_vt_strings();
    send( socket:soc, data:string( "VRFY ", vtstrings["lowercase_rand"], '\r\n' ) );
    vrfy_txt2 = smtp_recv_line( socket:soc );
    if( vrfy_txt2 && ! egrep( string:vrfy_txt2, pattern:"^252" ) ) {
      set_kb_item( name:"smtp/vrfy", value:TRUE );
      set_kb_item( name:"smtp/" + port + "/vrfy", value:TRUE );
      VULN = TRUE;
      report += string("'VRFY root' produces the following answer: ", vrfy_txt, "\n");
    }
  }
}

send( socket:soc, data:string( "EXPN root\r\n" ) );
expn_txt = smtp_recv_line( socket:soc, code:"(250|550)" );

if( expn_txt && egrep( string:expn_txt, pattern:"^(250|550)" ) ) {
  if( "Administrative prohibition" >!< expn_txt &&
      "Access Denied" >!< expn_txt &&
      "EXPN not available" >!< expn_txt &&
      "lists are confidential" >!< expn_txt &&
      "EXPN command has been disabled" >!< expn_txt && # https://msg.wikidoc.info/index.php/DISABLE_EXPAND
      "not available" >!< expn_txt ) {
    set_kb_item( name:"smtp/expn", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/expn", value:TRUE );
    VULN = TRUE;
    report += string("'EXPN root' produces the following answer: ", expn_txt, "\n");
  }
}

smtp_close( socket:soc, check_data:ehlotxt );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
