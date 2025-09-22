# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114383");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-02-21 15:53:16 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Bitvise SSH Server Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_bitvise_ssh_server_ssh_banner_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_bitvise_ssh_server_ftp_detect.nasl");
  script_mandatory_keys("bitvise/ssh_server/detected");

  script_xref(name:"URL", value:"https://www.bitvise.com/ssh-server");

  script_tag(name:"summary", value:"Consolidation of Bitvise SSH Server detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( ! get_kb_item( "bitvise/ssh_server/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source( make_list( "ssh-banner", "ftp" ) ) {
  version_list = get_kb_list( "bitvise/ssh_server/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:bitvise:winsshd:" );
if( ! cpe )
  cpe = "cpe:/a:bitvise:winsshd";

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", runs_key:"windows", desc:"Bitvise SSH Server Detection Consolidation" );

if( ssh_banner_ports = get_kb_list( "bitvise/ssh_server/ssh-banner/port" ) ) {

  extra += 'Remote Detection over SSH:\n';

  foreach port( ssh_banner_ports ) {
    extra += "  Port:        " + port + '/tcp\n';

    concluded = get_kb_item( "bitvise/ssh_server/ssh-banner/" + port + "/concluded" );
    if( concluded )
      extra += "  SSH banner:  " + concluded + '\n';

    register_product( cpe:cpe, location:port + "/tcp", port:port, service:"ssh" );
  }
}

if( ftp_ports = get_kb_list( "bitvise/ssh_server/ftp/port" ) ) {

  if( extra )
    extra += '\n';

  extra += 'Remote Detection over FTP:\n';

  foreach port( ftp_ports ) {
    extra += "  Port:        " + port + '/tcp\n';

    concluded = get_kb_item( "bitvise/ssh_server/ftp/" + port + "/concluded" );
    if( concluded )
      extra += "  FTP banner:  " + concluded;

    register_product( cpe:cpe, location:port + "/tcp", port:port, service:"ftp" );
  }
}

report = build_detection_report( app:"Bitvise SSH Server", version:detected_version,
                                 install:location, cpe:cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
