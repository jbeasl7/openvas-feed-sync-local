# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107665");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-05-25 16:57:20 +0200 (Sat, 25 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine ServiceDesk Plus Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_manageengine_servicedesk_plus_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_manageengine_servicedesk_plus_smb_detect.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_tag(name:"summary", value:"Consolidation of ManageEngine ServiceDesk Plus detections.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk");

  exit(0);
}

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

include("host_details.inc");

if( ! get_kb_item( "manageengine/servicedesk_plus/detected" ) )
  exit( 0 );

version = "unknown";
build = "unknown";

foreach proto( make_list( "smb", "http" ) ) {
  version_list = get_kb_list( "manageengine/servicedesk_plus/" + proto + "/*/version" );

  foreach ver( version_list ) {
    if( ver != "unknown" && version == "unknown" )
      version = ver;
  }

  builds_list = get_kb_list( "manageengine/servicedesk_plus/" + proto + "/*/build" );
  foreach buildnumber( builds_list ) {
    if( buildnumber != "unknown" && build == "unknown" )
      build = buildnumber;
  }

  if( version != "unknown" && build != "unknown" ) {
    CPE += ":" + version + ":b" + build;
    break;
  }
  else if( version != "unknown" ) {
    CPE += ":" + version;
    break;
  }
}

if( ! isnull( concl = get_kb_item( "manageengine/servicedesk_plus/smb/0/concluded" ) ) ) {
  insloc = get_kb_item( "manageengine/servicedesk_plus/smb/0/location" );
  extra += '\n- Local Detection over SMB:\n';
  extra += '\n  Location:      ' + insloc;
  extra += '\n  Concluded from:\n' + concl;

  register_product( cpe:CPE, location:insloc, port:0, service:"smb-login" );
}

if( http_ports = get_kb_list( "manageengine/servicedesk_plus/http/port" ) ) {

  if( extra )
    extra += '\n';

  extra += '\n- Remote Detection over HTTP(s):';

  foreach port( http_ports ) {
    concl  = get_kb_item( "manageengine/servicedesk_plus/http/" + port + "/concluded" );
    loc    = get_kb_item( "manageengine/servicedesk_plus/http/" + port + "/location" );
    extra += '\n';
    extra += '\n  Port:           ' + port + "/tcp";
    extra += '\n  Location:       ' + loc;

    if( concl )
      extra += '\n  Concluded from:\n' + concl;

    register_product( cpe:CPE, location:loc, port:port, service:"www" );
  }
}

set_kb_item( name:"manageengine/products/detected", value:TRUE );

report = build_detection_report( app:"ManageEngine ServiceDesk Plus",
                                 version:version,
                                 patch:build,
                                 install:"/",
                                 cpe:CPE );
if( extra ) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );

exit( 0 );
