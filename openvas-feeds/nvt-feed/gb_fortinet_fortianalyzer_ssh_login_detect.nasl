# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105198");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-02-10 17:03:19 +0100 (Tue, 10 Feb 2015)");
  script_name("Fortinet FortiAnalyzer Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/web-application-firewall/fortiweb");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiAnalyzer.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item( "fortinet/fortios/system_status" );
if( !system || "FortiAnalyzer" >!< system )
  exit( 0 );

port = get_kb_item( "fortinet/fortios/ssh-login/port" );

set_kb_item( name:"fortinet/fortianalyzer/detected", value:TRUE );
set_kb_item( name:"fortinet/fortianalyzer/ssh-login/detected", value:TRUE );
set_kb_item( name:"fortinet/fortianalyzer/ssh-login/port", value:port );

model = "unknown";
version = "unknown";
build = "unknown";
patch = "unknown";

# Platform Type                   : FAZ-3510G
# Platform Full Name              : FortiAnalyzer-3510G
# Version                         : v7.6.1-build3344 241023 (GA.M)
mod = eregmatch( string:system, pattern:'Platform Full Name\\s*:\\s*FortiAnalyzer-([^ \r\n]+)', icase:FALSE );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
  model = chomp( model );
  concluded = "    " + mod[0];

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


  ptchs = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
  if( ! isnull( ptchs[1] ) ) {
    patch = ptchs[1];
    if( concluded )
      concluded += '\n';
    concluded += "  " + ptchs[0];
  }

} else {
  # Seen in the CLI documentation for FortiAnalyzer 4.3
  # Version: FortiAnalyzer-800B v4.0,build0504,110627 (Interim)
  mod = eregmatch( string:system, pattern:'Version\\s*:\\s*FortiAnalyzer-([^ \r\n]+) v([0-9.]+),build([^, \r\n]+)', icase:FALSE );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
    model = chomp( model );
    concluded = "    " + mod[0];
  }
  if( ! isnull( mod[2] ) )
    version = mod[2];
  if( ! isnull( mod[3] ) )
     build = ereg_replace( string:mod[3], pattern:"^0", replace:"" );
}

if( ! concluded )
  concluded = system;

set_kb_item( name:"fortinet/fortianalyzer/ssh-login/" + port + "/model", value:model );
set_kb_item( name:"fortinet/fortianalyzer/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"fortinet/fortianalyzer/ssh-login/" + port + "/build", value:build );
set_kb_item( name:"fortinet/fortianalyzer/ssh-login/" + port + "/patch", value:patch );

if( concluded )
  set_kb_item( name:"fortinet/fortianalyzer/ssh-login/" + port + "/concluded", value:concluded );

exit( 0 );

