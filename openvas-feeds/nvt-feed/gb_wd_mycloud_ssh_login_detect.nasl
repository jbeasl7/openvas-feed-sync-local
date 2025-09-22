# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108490");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Western Digital My Cloud Products Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("wd-mycloud/ssh-login/cfg_file");

  script_tag(name:"summary", value:"SSH login-based detection of Western Digital My Cloud products.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "wd-mycloud/ssh-login/cfg_file" ) )
  exit( 0 );

if( ! port = get_kb_item( "wd-mycloud/ssh-login/port" ) )
  exit( 0 );

if( ! cfg_file = get_kb_item( "wd-mycloud/ssh-login/" + port + "/cfg_file" ) )
  exit( 0 );

model   = "unknown";
version = "unknown";

# nb: Tabs are used for the indentation in the file
# <config>
#       <sw_ver_1>2.30.183</sw_ver_1>
#       <sw_ver_2>2.30.183.0116.2018</sw_ver_2>
#       <hw_ver>MyCloudEX2Ultra</hw_ver>
# or:
# <config>
#       <sw_ver_1>2.11.178</sw_ver_1>
#       <sw_ver_2>2.11.178.0920.2018</sw_ver_2>
#       <hw_ver>WDMyCloudMirror</hw_ver>
# or:
# <config>
#       <sw_ver_1>2.31.149</sw_ver_1>
#       <sw_ver_2>2.31.149.1015.2018</sw_ver_2>
#       <hw_ver>MyCloudEX2Ultra</hw_ver>
#
# or:
# <config>
#       <sw_ver_1>5.08.115</sw_ver_1>
#       <sw_ver_2>5.08.115.1216.2020</sw_ver_2>
#       <hw_ver>MyCloudEX2Ultra</hw_ver>
#
mod = eregmatch( pattern:"<hw_ver>(WD)?MyCloud([^>]+)</hw_ver>", string:cfg_file );
if( ! mod[2] )
  exit( 0 );

model     = mod[2];
concluded = mod[0];

vers = eregmatch( pattern:"<sw_ver_1>([0-9.]+)</sw_ver_1>", string:cfg_file );
if( vers[1] ) {
  version = vers[1];
  if( concluded )
    concluded += '\n';
  concluded += vers[0];
}

set_kb_item( name:"wd-mycloud/ssh-login/" + port + "/concluded", value:concluded + '\nfrom "/etc/NAS_CFG/config.xml" file.' );

# nb: wd-mycloud/ssh-login/port is already set in gather-package-list.nasl
set_kb_item( name:"wd-mycloud/detected", value:TRUE );
set_kb_item( name:"wd-mycloud/ssh-login/detected", value:TRUE );
set_kb_item( name:"wd-mycloud/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"wd-mycloud/ssh-login/" + port + "/model", value:model );

exit( 0 );
