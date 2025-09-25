# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900815");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-08-14 14:09:35 +0200 (Fri, 14 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProFTPD Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/proftpd/detected");

  script_tag(name:"summary", value:"FTP based detection of the ProFTPD Server.");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

banner = ftp_get_banner( port:port );

if( banner && ( "ProFTPD" >< banner || "NASFTPD Turbo station" >< banner ) ) {
  version = "unknown";

  set_kb_item( name:"proftpd/detected", value:TRUE );
  set_kb_item( name:"proftpd/ftp/detected", value:TRUE );
  set_kb_item( name:"proftpd/ftp/port", value:port );
  set_kb_item( name:"proftpd/ftp/" + port + "/concluded", value:banner );

  # ProFTPD 1.2.9 Server (FTPD) [localhost]
  # ProFTPD 1.3.5e Server (Debian) [::ffff:<redacted>]
  # NASFTPD Turbo station 1.3.6 Server (ProFTPD) [::ffff:<redacted>]
  vers = eregmatch( pattern:"(ProFTPD|NASFTPD Turbo station) ([0-9.]+)([A-Za-z0-9]+)?( Server \(ProFTPD\))?",
                    string:banner );
  if( ! isnull( vers[2] ) ) {
    if( ! isnull( vers[3] ) ) {
      version = vers[2] + vers[3];
    } else {
      version = vers[2];
    }
  }

  set_kb_item( name:"proftpd/ftp/" + port + "/version", value:version );
}

exit( 0 );
