# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105459");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-19 16:21:45 +0100 (Thu, 19 Nov 2015)");
  script_name("Cisco Mobility Services Engine Detection");

  script_tag(name:"summary", value:"This Script get the via SSH detected Cisco Mobility Services Engine version");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_mse_cmx_web_iface_detect.nasl", "gb_cisco_mse_cmx_ssh_detect.nasl");
  script_mandatory_keys("cisco_mse/lsc");
  exit(0);
}


include("host_details.inc");

cpe = 'cpe:/a:cisco:mobility_services_engine';
source = 'SSH';

version = get_kb_item( "cisco_mse/ssh/version" );

if( ! version )
{
  source = 'HTTP(s)';
  version = get_kb_item( "cisco_mse/http/version" );
}

if( ! version ) exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

cpe += ':' + version;
set_kb_item( name:"cisco_mse/version", value:version );

register_product( cpe:cpe );

report = 'Detected Cisco Mobility Service Engine\nVersion: ' + version + '\nCPE: ' + cpe + '\nDetection source: ' + source;

log_message( port:0, data:report );
exit( 0 );

