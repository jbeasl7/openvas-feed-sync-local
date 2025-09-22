# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105159");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_version("2024-05-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2015-01-09 11:58:46 +0100 (Fri, 09 Jan 2015)");
  script_name("F5 BIG-IP Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of F5 BIG-IP devices.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_ip/VERSION_RAW");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

infos = get_kb_item( "f5/big_ip/VERSION_RAW" );
if( ! infos || "Product: BIG-IP" >!< infos )
  exit( 0 );

set_kb_item( name:"f5/big_ip/detected", value:TRUE );
set_kb_item( name:"f5/big_ip/ssh-login/detected", value:TRUE );

concluded = '  - "cat /VERSION" command response:\n' + infos;

if( get_kb_item( "f5/shell_is_tmsh" ) )
  nosh = TRUE;

_version = "unknown";
_build = "unknown";
_hotfix = 0;
install = "/";

version = eregmatch( pattern:'Version: ([^\r\n]+)', string:infos );
build   = eregmatch( pattern:'Build: ([^\r\n]+)', string:infos );
hotfix  = eregmatch( pattern:'Edition:.*Hotfix HF([^\r\n]+)', string:infos );
built   = eregmatch( pattern:'Built: ([^\r\n]+)', string:infos );
changelist = eregmatch( pattern:'Changelist: ([^\r\n]+)', string:infos );

if( ! isnull( version[1] ) ) {
  _version = version[1];
  set_kb_item( name:"f5/big_ip/version", value:_version );
}

if( ! isnull( build[1] ) ) {
  _build = build[1];
  set_kb_item( name:"f5/big_ip/build", value:_build );
}

if( ! isnull( hotfix[1] ) ) {
  _hotfix = hotfix[1];
} else {
  if( _build ) {
    h = eregmatch( pattern:"\s*([0-9]+)\.[0-9]+", string:_build );
    if( ! isnull( h[1] ) )
      _hotfix = h[1];
  }
}

set_kb_item( name:"f5/big_ip/hotfix", value:_hotfix );

if( ! isnull( built[1] ) )
  set_kb_item( name:"f5/big_ip/built", value:built[1] );

if( ! isnull( changelist[1] ) )
  set_kb_item( name:"f5/big_ip/changelist", value:changelist[1] );

if( nosh ) {
  modules_cmd = "list sys provision";
  modules_res = ssh_cmd_exec( cmd:modules_cmd, nosh:TRUE );
} else {
  modules_cmd = "tmsh list sys provision";
  modules_res = ssh_cmd_exec( cmd:modules_cmd );
}

if( ! isnull( modules_res ) ) {

  concluded += '\n\n  - "' + modules_cmd + '" command response:\n' + modules_res;

  modules_lines = split( modules_res );
  for( i = 0; i < max_index( modules_lines ); i++ ) {
    if( "{ }" >< modules_lines[i] )
      continue;

    if( module = eregmatch( pattern:'sys provision ([^ \r\n{]+) \\{[\r\n]+', string:modules_lines[i] ) )
      active_modules += module[1] + ",";
  }
}

if( active_modules =~ ",$" )
  active_modules = ereg_replace( pattern:"(,)$", replace:"", string:active_modules );

active_modules = toupper( active_modules );

if( active_modules )
  set_kb_item( name:"f5/big_ip/active_modules", value:active_modules );

cpe = "cpe:/h:f5:big-ip";

if( _version != "unknown" )
  cpe += ":" + _version;

# At least 17.x through 13.x seems to be running on CentOS:
#
# https://my.f5.com/manage/s/article/K3645
#
# nb: There seems to be no archived version of the page above or of the "older" one:
#
# https://support.f5.com/csp/article/K3645
#
# so only the versions 17.x through 13.x have been added here.
#
if( _version =~ "^1[4-7]\." ) {
  os_name = "CentOS";
  os_cpe = "cpe:/o:centos:centos";
  os_version = "7.3";
}

else if( _version =~ "^13\." ) {
  os_name = "CentOS";
  os_cpe = "cpe:/o:centos:centos";
  os_version = "6.8";
}

# nb: If the version is unknown just registering a more generic OS
else {
  os_name = "Linux";
  os_cpe = "cpe:/o:linux:kernel";
  os_version = "unknown";
}

os_register_and_report( os:os_name, cpe:os_cpe, version:os_version, port:0, desc:"F5 BIG-IP Detection (SSH Login)", runs_key:"unixoide" );

register_product( cpe:cpe, location:install, port:0, service:"ssh-login" );

report = 'Detected F5 BIG-IP\n\n' +
         "Version: " + _version + '\n' +
         "Build:   " + _build + '\n';

if( _hotfix )
  extra = " - Hotfix: " + _hotfix;

if( active_modules ) {
  if( extra )
    extra += '\n';
  extra += " - Active Modules: " + active_modules;
}

report = build_detection_report( app:"F5 BIG-IP",
                                 version:_version,
                                 build:_build,
                                 install:install,
                                 cpe:cpe,
                                 concluded:concluded,
                                 extra:extra );

log_message( port:0, data:chomp( report ) );
exit( 0 );
