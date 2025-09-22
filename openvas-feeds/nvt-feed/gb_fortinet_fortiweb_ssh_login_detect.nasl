# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105199");
  script_version("2024-12-17T05:05:41+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-02-10 17:03:19 +0100 (Tue, 10 Feb 2015)");
  script_name("Fortinet FortiWeb Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/web-application-firewall/fortiweb");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiWeb.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item( "fortinet/fortios/system_status" );
if( ! system || "FortiWeb" >!< system )
  exit( 0 );

port = get_kb_item( "fortinet/fortios/ssh-login/port" );

set_kb_item( name:"fortinet/fortiweb/detected", value:TRUE );
set_kb_item( name:"fortinet/fortiweb/ssh-login/detected", value:TRUE );
set_kb_item( name:"fortinet/fortiweb/ssh-login/port", value:port );

model = "unknown";
version = "unknown";
build = "unknown";
patch = "unknown";

# FortiWeb-Demo $ get system status
# International Version: FortiWeb-VM 7.6.0,build0962(GA.F),240620
# Serial-Number: FWBVMSTM<redacted>
# license type: remote
# Bios version: 04000002
# Log hard disk: Available
# Hostname: FortiWeb-Demo
# Operation Mode: Reverse Proxy
# FIPS-CC mode: disabled
# System Uptime: [119 day(s) 15 hour(s) 11 min(s)]
# Current HA mode: standalone
# Database Status: Available

mod = eregmatch( string:system, pattern:'Version\\s*:\\s*FortiWeb-([^ ]+)[^\r\n]*' );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
  model = chomp( model );
  concluded = "  " + mod[0];
}

vers = eregmatch( string:system, pattern:"Version\s*:\s*FortiWeb-[^ ]* ([0-9.]+)," );

if( ! isnull( vers[1] ) ) {
  version = vers[1];
  for( i = 0; i < strlen( version ); i++ ) {
    if( version[i] == "." )
      continue;

    v += version[i];

    if( i < ( strlen( version ) - 1 ) )
      v += ".";
  }
  version = v;
  # nb: No need to add this to the "concluded" reporting as it is in the same line as the model
}

bld = eregmatch( string:system, pattern:",build([^,]+)" );
# nb: No need to add this to the "concluded" reporting as it is in the same line as the version/model
if( ! isnull( bld[1] ) )
  build = ereg_replace( string:bld[1], pattern:"^0", replace:"" );

ptch = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
if( ! isnull( ptch[1] ) ) {
  patch = ptch[1];
  if( concluded )
    concluded += '\n';
  concluded += "  " + ptch[0];
}

if( ! concluded )
  concluded = system;

set_kb_item( name:"fortinet/fortiweb/ssh-login/" + port + "/model", value:model );
set_kb_item( name:"fortinet/fortiweb/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"fortinet/fortiweb/ssh-login/" + port + "/build", value:build );
set_kb_item( name:"fortinet/fortiweb/ssh-login/" + port + "/patch", value:patch );

if( concluded )
  set_kb_item( name:"fortinet/fortiweb/ssh-login/" + port + "/concluded", value:concluded );

exit( 0 );
