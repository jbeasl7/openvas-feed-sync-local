# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105814");
  script_version("2024-12-18T05:05:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-12-18 05:05:50 +0000 (Wed, 18 Dec 2024)");
  script_tag(name:"creation_date", value:"2016-07-19 09:58:46 +0200 (Tue, 19 Jul 2016)");
  script_name("Fortinet FortiManager Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiManager.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item( "fortinet/fortios/system_status" );
if( ! system || "FortiManager" >!< system )
  exit( 0 );

port = get_kb_item( "fortinet/fortios/ssh-login/port" );

set_kb_item( name:"fortinet/fortimanager/detected", value:TRUE );
set_kb_item( name:"fortinet/fortimanager/ssh-login/detected", value:TRUE );
set_kb_item( name:"fortinet/fortimanager/ssh-login/port", value:port );

model = "unknown";
version = "unknown";
build = "unknown";
patch = "unknown";

# Platform Type : FMG-VM64
# Platform Full Name : FortiManager-VM64
# Version : v6.0.1-build0150 180606 (GA)
mod = eregmatch( string:system, pattern:'Platform Full Name\\s*:\\s*FortiManager-([^ \r\n]+)', icase:FALSE );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
  model = chomp( model );
  concluded = "    " + mod[0];
}

vers = eregmatch( string:system, pattern:"Version\s*:\s*v([0-9.]+).*", icase:FALSE );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  if( concluded )
    concluded += '\n';
  concluded += "    " + vers[0];
}

bld = eregmatch( string:system, pattern:'Version\\s*:.+-build([^ \r\n]+)', icase:FALSE );
# nb: No need to add this to the "concluded" reporting as it is in the same line as the version
if( ! isnull( bld[1] ) )
  build = ereg_replace( string:bld[1], pattern:"^0", replace:"" );

if( ! concluded )
  concluded = system;

set_kb_item( name:"fortinet/fortimanager/ssh-login/" + port + "/model", value:model );
set_kb_item( name:"fortinet/fortimanager/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"fortinet/fortimanager/ssh-login/" + port + "/build", value:build );
set_kb_item( name:"fortinet/fortimanager/ssh-login/" + port + "/patch", value:patch );

if( concluded )
  set_kb_item( name:"fortinet/fortimanager/ssh-login/" + port + "/concluded", value:concluded );

exit( 0 );
