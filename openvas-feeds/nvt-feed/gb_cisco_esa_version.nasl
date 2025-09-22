# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105440");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-09 13:54:40 +0100 (Mon, 09 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco Email Security Appliance Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_esa_web_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("cisco_esa/installed");

  script_tag(name:"summary", value:"This Script get the via HTTP(s) or SSH detected Cisco Email Security Appliance
version");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

source = 'SSH';

version = get_kb_item("cisco_esa/version/ssh");
if( ! version )
{
  version = get_kb_item("cisco_esa/version/http");
  source = 'HTTP(s)';
}

if( ! version ) exit( 0 );

model = get_kb_item("cisco_esa/model/ssh");
if( ! model ) model = get_kb_item("cisco_esa/model/http");

set_kb_item( name:"cisco_esa/version", value:version );

if( model ) set_kb_item( name:"cisco_esa/model", value:model );

cpe = 'cpe:/h:cisco:email_security_appliance:' + version;

register_product( cpe:cpe );

os_register_and_report( os:"Cisco AsyncOS", cpe:"cpe:/o:cisco:asyncos:" + version, banner_type:source, desc:"Cisco Email Security Appliance Detection", runs_key:"unixoide" );

report = 'Detected Cisco Email Security Appliance\nVersion: ' + version + '\nCPE: ' + cpe;
if( model ) report += '\nModel: ' + model;

report += '\nDetection source: ' + source;

log_message( port:0, data:report );
exit( 0 );

