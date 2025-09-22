# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108351");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("hyperip/ssh-login/show_version_or_uname");

  script_tag(name:"summary", value:"SSH login-based detection of a NetEx HyperIP virtual appliance.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "hyperip/ssh-login/show_version_or_uname" ) ) exit( 0 );

version = "unknown";

port = get_kb_item( "hyperip/ssh-login/port" );

show_version = get_kb_item( "hyperip/ssh-login/" + port + "/show_version" );
uname        = get_kb_item( "hyperip/ssh-login/" + port + "/uname" );

if( ! show_version && ! uname ) exit( 0 );

# Product Version ............ HyperIP 6.1.1 11-Jan-2018 13:09 (build 2) (r9200)
vers = eregmatch( pattern:"Product Version([^\n]+)HyperIP ([0-9.]+)", string:show_version );
if( vers[2] ) {
  version = vers[2];
  set_kb_item( name:"hyperip/ssh-login/" + port + "/concluded", value:vers[0] + " from 'showVersion' command" );
} else {
  set_kb_item( name:"hyperip/ssh-login/" + port + "/concluded", value:uname );
}

# nb: hyperip/ssh-login/port is already set in gather-package-list.nasl
set_kb_item( name:"hyperip/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-login/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-login/" + port + "/version", value:version );

exit( 0 );
