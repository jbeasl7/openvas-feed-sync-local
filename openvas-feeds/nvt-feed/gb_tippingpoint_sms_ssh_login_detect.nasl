# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108568");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Trend Micro TippingPoint Security Management System (SMS) Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("tippingpoint/sms/ssh-login/version_cmd_or_uname");

  script_tag(name:"summary", value:"SSH login-based detection of a Trend Micro
  TippingPoint Security Management System (SMS).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "tippingpoint/sms/ssh-login/version_cmd_or_uname" ) )
  exit( 0 );

version  = "unknown";
port     = get_kb_item( "tippingpoint/sms/ssh-login/port" );
vers_cmd = get_kb_item( "tippingpoint/sms/ssh-login/" + port + "/version_cmd" );
uname    = get_kb_item( "tippingpoint/sms/ssh-login/" + port + "/uname" );

if( ! vers_cmd && ! uname )
  exit( 0 );

# Version:
#     5.0.0.106258
#
# Patch:
#     5.0.0.106258.1
vers = eregmatch( pattern:"Version:\s+([0-9.]+)", string:vers_cmd );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/concluded", value:vers[0] + " from 'version' command" );
} else {
  set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/concluded", value:uname + " from login banner" );
}

# nb: tippingpoint/sms/ssh-login/port is already set in gather-package-list.nasl
set_kb_item( name:"tippingpoint/sms/detected", value:TRUE );
set_kb_item( name:"tippingpoint/sms/ssh-login/detected", value:TRUE );
set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/version", value:version );

exit( 0 );
