# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105344");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-04 10:33:25 +0200 (Fri, 04 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("OpenVPN Access Server Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenVPN Access Server.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

vers = "unknown";

issue = get_kb_item( "ssh/login/openvpn_as/etc_issue" );
if( issue && "OpenVPN Access Server" >< issue ) {
  version = eregmatch( pattern:"OpenVPN Access Server Appliance ([0-9.]+)", string:issue );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    concluded = version[0];
    concluded_file = "/etc/issue";
  }
  oas_installed = TRUE;
}

if( ! oas_installed || vers == "unknown" ) {
  soc = ssh_login_or_reuse_connection();
  if( soc ) {
    file = "/usr/local/openvpn_as/etc/VERSION";
    buf = ssh_cmd( socket:soc, cmd:"cat " + file );
    close( soc );
    if( "AS_VERSION=" >< buf ) {
      version = eregmatch( pattern:"AS_VERSION=([0-9.]+)", string:buf );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        concluded = buf;
        concluded_file = file;
      }
      oas_installed = TRUE;
    }
  }
}

if( oas_installed ) {
  port = get_kb_item( "openvpn/ssh-login/port" );
  set_kb_item( name:"openvpn/access_server/detected", value:TRUE );
  set_kb_item( name:"openvpn/access_server/ssh-login/port", value:port );

  set_kb_item( name:"openvpn/access_server/ssh-login/" + port + "/version", value:vers );
  if( concluded )
    set_kb_item( name:"openvpn/access_server/ssh-login/" + port + "/concluded", value:concluded );
  if( concluded_file )
    set_kb_item( name:"openvpn/access_server/ssh-login/" + port + "/concluded_file", value:concluded_file );
}

exit( 0 );
