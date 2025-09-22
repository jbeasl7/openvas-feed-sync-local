# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111085");
  script_version("2023-11-10T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-11-10 05:05:18 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-02-04 15:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Exchange Server Detection (SMTP/POP3/IMAP)");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl", "popserver_detect.nasl", "imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"The script checks the SMTP/POP3/IMAP server
  banner for the presence of an Microsoft Exchange Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
#include("cpe.inc");

ports = smtp_get_ports();
foreach port( ports ) {

  banner = smtp_get_banner( port:port );
  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

  if( "Microsoft Exchange Internet Mail Service" >< banner || "NTLM LOGIN" >< banner ||
      "Microsoft SMTP MAIL" >< banner || "Microsoft ESMTP MAIL Service" >< banner ||
      "ESMTP Exchange Server" >< banner || "ESMTP Microsoft Exchange" >< banner ||
      ( ( "This server supports the following commands" >< help || "End of HELP information" >< help ) &&
          "Service closing transmission channel" >< quit && "Resetting" >< rset && "OK" >< noop ) ) {

    version = "unknown";
    install = port + "/tcp";

    ver = eregmatch( pattern:"Version: ([0-9.]+)", string:banner );
    if( ver[1] )
      version = ver[1];

    if( version == "unknown" ) {
      ver = eregmatch( pattern:"Service ([0-9.]+)", string:banner );
      if( ver[1] )
        version = ver[1];
    }

    if( version == "unknown" ) {
      ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner );
      if( ver[1] )
        version = ver[1];
    }

    set_kb_item( name:"microsoft/exchange_server/smtp/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/smtp/" + port + "/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/remote/detected", value:TRUE );

    #cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:" );
    #if( isnull( cpe ) )
      cpe = "cpe:/a:microsoft:exchange_server";

    register_product( cpe:cpe, location:install, port:port, service:"smtp");

    log_message( data:build_detection_report( app:"Microsoft Exchange",
                                              install:install,
                                              cpe:cpe,
                                              extra:"Service version: " + version,
                                              concluded:banner ),
                                              port:port );
  }
}

ports = imap_get_ports();
foreach port( ports ) {

  banner = imap_get_banner( port:port );

  if( "The Microsoft Exchange IMAP4 service is ready" >< banner ||
      "Microsoft Exchange Server" >< banner ) {

    version = "unknown";
    install = port + "/tcp";

    ver = eregmatch( pattern:"Version ([0-9.]+)", string:banner );
    if( ver[1] )
      version = ver[1];

    if( version == "unknown" ) {
      ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner );
      if( ver[1] )
        version = ver[1];
    }

    set_kb_item( name:"microsoft/exchange_server/imap/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/imap/" + port + "/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/detected", value:TRUE );
    set_kb_item( name:"microsoft/exchange_server/remote/detected", value:TRUE );

    #cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:" );
    #if( isnull( cpe ) )
      cpe = "cpe:/a:microsoft:exchange_server";

    register_product( cpe:cpe, location:install, port:port, service:"imap" );

    log_message( data:build_detection_report( app:"Microsoft Exchange",
                                              install:install,
                                              cpe:cpe,
                                              extra:"Service version: " + version,
                                              concluded:banner ),
                                              port:port );
  }
}

port = pop3_get_port( default:110 );
banner = pop3_get_banner( port:port );

if( "Microsoft Windows POP3 Service Version" >< banner ||
    "The Microsoft Exchange POP3 service is ready." >< banner ||
    "Microsoft Exchange Server" >< banner ||
    "Microsoft Exchange POP3-Server" >< banner ) {

  version = "unknown";
  install = port + "/tcp";

  ver = eregmatch( pattern:"Version ([0-9.]+)", string:banner );
  if( ver[1] )
    version = ver[1];

  if( version == "unknown" ) {
    ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner );
    if( ver[1] )
      version = ver[1];
  }

  set_kb_item( name:"microsoft/exchange_server/pop3/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/pop3/" + port + "/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/remote/detected", value:TRUE );

  #cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:" );
  #if( isnull( cpe ) )
    cpe = "cpe:/a:microsoft:exchange_server";

  register_product( cpe:cpe, location:install, port:port, service:"pop3" );
  log_message( data:build_detection_report( app:"Microsoft Exchange",
                                            install:install,
                                            cpe:cpe,
                                            extra:"Service version: " + version,
                                            concluded:banner ),
                                            port:port );
}

exit( 0 );
