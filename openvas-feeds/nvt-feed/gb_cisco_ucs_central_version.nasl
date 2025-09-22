# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105573");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-17 14:04:35 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Central Version Detection");

  script_tag(name:"summary", value:"This Script consolidate the via SSH or HTTP(s) detected version of Cisco UCS Central for later use.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ucs_central_version_ssh.nasl", "gb_cisco_ucs_central_version_http.nasl");
  script_mandatory_keys("cisco_ucs_central/installed");
  exit(0);
}


include("host_details.inc");

source = "ssh";

version = get_kb_item( "cisco_ucs_central/" + source  + "/version" );
if( ! version )
{
  source = "http";
  version = get_kb_item( "cisco_ucs_central/" + source  + "/version" );
}

if( ! version || version == "unknown" ) exit( 0 );

cpe = 'cpe:/a:cisco:ucs_central_software' + ':' + version;

register_product( cpe:cpe, location:source );

set_kb_item( name:"cisco_ucs_central/version", value:version );

log_message( data: build_detection_report( app:"Cisco UCS Central",
                                           version:version,
                                           install:source,
                                           cpe:cpe,
                                           concluded: source ),
             port:0 );

exit(0);
