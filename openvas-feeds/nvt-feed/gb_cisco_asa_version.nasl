# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105222");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-18 12:37:03 +0100 (Wed, 18 Feb 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco ASA Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco ASA");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! system = get_kb_item( "cisco/show_version" ) ) exit( 0 );

if( "Cisco Adaptive Security Appliance" >!< system ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:cisco:asa';
cpe2 = 'cpe:/o:cisco:adaptive_security_appliance_software';

version = eregmatch( pattern:'Cisco Adaptive Security Appliance Software Version ([^ \r\n]+)', string:system );

if( ! isnull( version[1] ) ) {
  vers = version[1];
  set_kb_item( name:"cisco_asa/version", value:vers );
  cpe += ':' + vers;
  cpe2 += ':' + vers;
}

hardware = eregmatch( pattern:"Hardware:\s*([^,]+)", string:system );

if( ! isnull( hardware[1] ) ) {
   hw = hardware[1];
   set_kb_item( name:"cisco_asa/model", value:hw );
}

register_product( cpe:cpe, location:'ssh' );
os_register_and_report( os:"Cisco ASA", cpe:cpe2, banner_type:"SSH login", banner:system, desc:"Cisco ASA Detection (SSH)", runs_key:"unixoide" );

report = 'Detected Cisco ASA (ssh)\n\n' +
         'Version: ' + vers + '\n';

if( hw )
  report += 'Model:   ' + hw + '\n';

report += 'CPE:     ' + cpe;

log_message( port:0, data:report );

exit( 0 );
