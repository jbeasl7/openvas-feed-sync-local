# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108039");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/avm/fritzbox_ftp/detected");

  script_tag(name:"summary", value:"FTP based detection of AVM FRITZ!Box devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

if( banner && "FRITZ!Box" >< banner && "FTP server ready." >< banner ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/ftp/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/ftp/port", value:port );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/concluded", value:banner );

  type = "unknown";
  model = "unknown";
  fw_version = "unknown";

  mo = eregmatch( pattern:'FRITZ!Box(FonWLAN|WLAN)?([0-9]+((v[0-9]+|vDSL|SL|LTE|Cable))?)', string:banner );
  if( ! isnull( mo[1] ) ) type = mo[1];
  # Adding spaces as the model in the FTP banner doesn't have any spaces
  # e.g. FRITZ!BoxFonWLAN7270v2 FTP server ready. / FRITZ!Box6490Cable(kdg) FTP server ready.
  if( ! isnull( mo[2] ) ) {
    mo[2] = ereg_replace( pattern:"(v[0-9]+|vDSL|SL|LTE|Cable)", string:mo[2], replace:" \1" );
    model = mo[2];
  }

  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );
