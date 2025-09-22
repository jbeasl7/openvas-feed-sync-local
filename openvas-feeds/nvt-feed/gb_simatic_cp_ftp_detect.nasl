# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108345");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-20 09:28:27 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC CP Device Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/siemens/simatic_cp/detected");

  script_tag(name:"summary", value:"This script performs FTP based detection of Siemens SIMATIC CP devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

# CP 343-1 FTP-Server V2.00 ready for new user
# CP 343-1 IT FTP-Server V1.07 ready for new user
# CP 443-1 IT FTP-Server V1.07 ready for new user
if( banner && banner =~ "CP ([0-9\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" ) {

  model   = "unknown";
  version = "unknown";
  set_kb_item( name:"simatic_cp/detected", value:TRUE );
  set_kb_item( name:"simatic_cp/ftp/detected", value:TRUE );
  set_kb_item( name:"simatic_cp/ftp/port", value:port );

  mod = eregmatch( pattern:"CP ([0-9\-]+) (IT )?FTP-Server", string:banner );
  if( ! isnull( mod[1] ) ) model = mod[1];

  set_kb_item( name:"simatic_cp/ftp/" + port + "/concluded", value:banner );
  set_kb_item( name:"simatic_cp/ftp/" + port + "/model", value:model );
  set_kb_item( name:"simatic_cp/ftp/" + port + "/version", value:version );
}

exit( 0 );
