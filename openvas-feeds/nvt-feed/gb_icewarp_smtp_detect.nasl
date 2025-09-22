# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113776");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-11-04 10:10:10 +0100 (Wed, 04 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IceWarp Mail Server Detection (SMTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/icewarp/mailserver/detected");

  script_tag(name:"summary", value:"SMTP based detection of IceWarp Mail Server.");

  exit(0);
}

include( "host_details.inc" );
include( "smtp_func.inc" );
include( "port_service_func.inc" );

port = smtp_get_port( default: 25 );

if( ! banner = smtp_get_banner( port: port ) )
  exit( 0 );

if( banner =~ "IceWarp" ) {
  version = "unknown";
  concluded = banner;

  set_kb_item( name: "icewarp/mailserver/detected", value: TRUE );
  set_kb_item( name: "icewarp/mailserver/smtp/detected", value: TRUE );
  set_kb_item( name: "icewarp/mailserver/smtp/port", value: port );

  vers = eregmatch( string: banner, pattern: "IceWarp ([0-9.]+)", icase: TRUE );
  if( isnull(vers[1] ) ) {
    help_banner = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
    if( help_banner && help_banner =~ "This is IceWarp [0-9]" ) {
      vers = eregmatch( pattern: "This is IceWarp ([0-9.]+)", string: help_banner );
      concluded += '\nHelp Banner: ' + vers[0];
    }
  }

  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name: "icewarp/mailserver/smtp/" + port + "/version", value: version );
  set_kb_item( name: "icewarp/mailserver/smtp/" + port + "/concluded", value: concluded );
}

exit( 0 );
