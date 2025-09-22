# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105155");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-01-07 16:37:56 +0100 (Wed, 07 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("McAfee Email Gateway Version");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("mcafee/OS");

  script_tag(name:"summary", value:"This script performs SSH based detection of McAfee Email Gateway");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

infos = ssh_cmd_exec( cmd:"cat /.build" );

if( "s.label.product Email Gateway" >!< infos || "s.labelshort.vendor McAfee" >!< infos ) exit( 0 );

set_kb_item( name:"mcafee_email_gateway/LSC", value:TRUE );

product_version = eregmatch( pattern:'s.product.version ([^\r\n]+)', string:infos );
product_build   = eregmatch( pattern:'s.product.build ([^\r\n]+)', string:infos );
product_package = eregmatch( pattern:'s.product.package ([^\r\n]+)', string:infos );
product_name    = eregmatch( pattern:'s.label.product ([^\r\n]+)', string:infos );

if( ! isnull( product_version[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_version', value:product_version[1] );
  version += product_version[1];
}

if( ! isnull( product_build[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_build', value:product_build[1] );
  version += '.' + product_build[1];
}

if( ! isnull( product_package[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_package', value:product_package[1] );
  version += '.' + product_package[1];
}

product = 'McAfee Email Gateway';
if( ! isnull( product_name[1] ) )
  product = product_name[1];

set_kb_item( name:'mcafee_email_gateway/product_name', value:product );

foreach line ( split( infos ) )
{
 if( installed_patch = eregmatch( pattern:'s.product.patch.([^ ]+)', string:line ) )
 {
   patches += installed_patch[1] + ' ';
   report_patches += installed_patch[1] + '\n';
 }
}

if( patches )
  set_kb_item( name:"mcafee_email_gateway/patches", value:patches );

os = ssh_cmd_exec( cmd:'cat /.mlos-version' );

if( "McAfee Linux Operating System" >< os )
{
  os_version = 'unknown';
  os_vers = eregmatch( pattern:'Version: ([^\r\n]+)', string:os );

  if( ! isnull( os_vers[1] ) )
    os_version = os_vers[1];

  os_cpe_vers = str_replace( string:os_version, find:"-", replace:"_" );

  os_register_and_report( os:"McAfee Linux Operating System (" + os_version + ")", cpe:"cpe:/o:mcafee:linux_operating_system:" + os_cpe_vers, banner_type:"SSH login", desc:"McAfee Email Gateway Version", runs_key:"unixoide" );
}

cpe = 'cpe:/a:mcafee:email_gateway';
if( version != 'unknown' )
  cpe += ':' + version;

register_product( cpe:cpe, location:'ssh' );

report = 'Detected McAfee ' + product  + ' (ssh)\n' +
         'Version: ' +  version + '\n' +
         'CPE: ' + cpe + '\n';

if( patches )
  report += '\nList of installed patches: \n\n' + report_patches;

log_message( port:0, data: report );
exit( 0 );
