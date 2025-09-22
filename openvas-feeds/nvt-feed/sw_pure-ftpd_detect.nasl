# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111110");
  script_version("2025-07-15T05:43:28+0000");
  script_tag(name:"last_modification", value:"2025-07-15 05:43:28 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-07-12 17:00:00 +0200 (Tue, 12 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Pure-FTPd FTP Server Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pure_ftpd/detected");

  script_tag(name:"summary", value:"FTP based detection of a Pure-FTPd FTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.pureftpd.org");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
command = ftp_get_cmd_banner( port:port, cmd:"HELP" );

if( "Welcome to Pure-FTPd" >< banner || "Welcome to PureFTPd" >< banner ) {
  installed = TRUE;
  concluded = banner;
} else if( "Pure-FTPd - http://pureftpd.org" >< command ) {
  installed = TRUE;
  concluded = command;
}

if( installed ) {

  install = port + "/tcp";
  version = "unknown";

  # 220---------- Welcome to Pure-FTPd 1.0.49 [privsep] [TLS] ----------
  # 220-=(<*>)=-.:. (( Welcome to PureFTPd 1.0.10 )) .:.-=(<*>)=-
  # 220 Welcome to PureFTPD!
  ver = eregmatch( pattern:"Welcome to Pure[-]?FTPd ([0-9.]+)", string:banner );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    concluded = ver[0];
  }

  set_kb_item( name:"pure-ftpd/detected", value:TRUE );
  set_kb_item( name:"pure-ftpd/ftp/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:pureftpd:pure-ftpd:" );
  if( ! cpe )
    cpe = "cpe:/a:pureftpd:pure-ftpd";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"Pure-FTPd",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
