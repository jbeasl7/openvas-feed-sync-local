# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105571");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-17 12:43:49 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Central Detection (SSH)");

  script_tag(name:"summary", value:"'This script performs SSH based version detection of Cisco UCS Central");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  exit(0);
}

include("host_details.inc");

source = "ssh";

show_version = get_kb_item( "cisco/show_version" );

if( ! show_version || "Cisco UCS Central" >!< show_version ) exit( 0 );

cpe = 'cpe:/a:cisco:ucs_central_software';
set_kb_item( name:"cisco_ucs_central/installed", value:TRUE );

sw = split( show_version );

foreach line ( sw )
{
  if( line =~ "^core\s+Base System" )
  {
    version = eregmatch( pattern:"^core\s+Base System\s+([0-9]+[^ ]+)", string:line );
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      cpe += ':' + vers;
      set_kb_item( name:"cisco_ucs_central/" + source + "/version", value:vers );
      break;
    }
  }
}
report = build_detection_report( app:"Cisco UCS Central", version:vers, install:source, cpe:cpe, concluded:"show version" );
log_message( port:0, data:report );

exit( 0 );

