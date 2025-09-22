# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900815");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-14 14:09:35 +0200 (Fri, 14 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ProFTPD Server Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/proftpd/detected");

  script_xref(name:"URL", value:"http://www.proftpd.org");

  script_tag(name:"summary", value:"FTP based detection of the ProFTPD Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

if( banner && ( "ProFTPD" >< banner || "NASFTPD Turbo station" >< banner ) ) {

  ver = "unknown";
  set_kb_item( name:"ProFTPD/Installed", value:TRUE );

  ftpVer = eregmatch( pattern:"(ProFTPD|NASFTPD Turbo station) ([0-9.]+)([A-Za-z0-9]+)?( Server \(ProFTPD\))?", string:banner );

  if( ftpVer[2] ) {
    if( ftpVer[3] ) {
      ver = ftpVer[2] + ftpVer[3];
    } else {
      ver = ftpVer[2];
    }
    set_kb_item( name:"ProFTPD/" + port + "/Ver", value:ver );
  }

  cpe = build_cpe( value:ftpVer[2], exp:"^([0-9.]+)", base:"cpe:/a:proftpd:proftpd:" );
  if( ftpVer[2] && ftpVer[3] && ! isnull( cpe ) )
    cpe = cpe + ":" + ftpVer[3];
  if( ! cpe )
    cpe = 'cpe:/a:proftpd:proftpd';

  register_product( cpe:cpe, location:port + '/tcp', port:port, service:"ftp" );

  log_message( data:build_detection_report( app:"ProFTPD",
                                            version:ver,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:banner ),
                                            port:port );
}

exit( 0 );
