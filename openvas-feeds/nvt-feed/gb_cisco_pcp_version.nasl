# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105546");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-15 16:25:34 +0100 (Mon, 15 Feb 2016)");
  script_name("Cisco Prime Collaboration Provisioning Detection");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco Prime Collaboration Provisioning");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_pcp/show_ver");
  exit(0);
}


include("host_details.inc");

show_ver = get_kb_item("cisco_pcp/show_ver");

if( ! show_ver || "Cisco Prime Collaboration Provisioning" >!< show_ver ) exit( 0 );

cpe = 'cpe:/a:cisco:prime_collaboration_provisioning';
vers = 'unknown';

version = eregmatch( pattern:'[^ ]Version\\s*:\\s*([0-9]+[^\r\n]+)', string:show_ver ); # for example: 10.0.0.791
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'cisco_pcp/version', value:vers );
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:'Cisco Prime Collaboration Provisioning',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: 'show version' ),
             port:0 );

exit( 0 );
