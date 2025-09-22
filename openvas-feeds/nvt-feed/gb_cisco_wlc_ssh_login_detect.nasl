# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105429");
  script_version("2022-12-16T10:18:13+0000");
  script_tag(name:"last_modification", value:"2022-12-16 10:18:13 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-10-30 14:08:04 +0100 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco Wireless LAN Controller (WLC) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "ssh_authorization_init.nasl", "ssh_authorization.nasl");
  script_require_ports("Services/ssh", 22);
  # nb: ssh/cisco/wlc/detected is also set by ssh_detect.nasl when hitting a libssh banner...
  script_mandatory_keys("ssh/cisco/wlc/detected", "login/SSH/required_login_info_given");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco Wireless LAN Controller
  (WLC) devices.");

  exit(0);
}

if( ! get_kb_item( "ssh/cisco/wlc/detected" ) )
  exit( 0 );

include("ssh_func.inc");

port = kb_ssh_transport();
if( ! get_port_state( port ) )
  exit( 0 );

if( ! banner = ssh_get_serverbanner( port:port ) )
  exit( 0 );

if( "libssh" >< banner ) {
  tries = 1;
  # In between 8.5.x and 8.10.x Cisco switched to use SSH-2.0-libssh_0.7.7 (and probably later or
  # earlier versions of libssh depending on the firmware) instead of SSH-2.0-CISCO_WLC.
  # The latter was some kind of Telnet like SSH implementation (using a User: and Password: prompt
  # for the login). That's why there are different ways to login implemented below.
  using_libssh = TRUE;
} else {
  # nb: This seems to have been used in the past because the device was slow to respond with the
  # old implementation.
  tries = 3;
}

for( i = 0; i < tries; i++ ) {

  # nb: See the note on the difference above...
  if( using_libssh ) {

    if( ssh_dont_try_login( port:port ) )
      continue;

    if( ! soc = ssh_login_or_reuse_connection() )
      continue;

    if( ! buf1 = ssh_cmd( socket:soc, cmd:"show sysinfo", nosh:TRUE, nosu:TRUE, pty:TRUE ) ) {
      ssh_close_connection( socket:soc );
      continue;
    }

    buf = buf1;

    buf2 = ssh_cmd( socket:soc, cmd:"show inventory", nosh:TRUE, nosu:TRUE, pty:TRUE );
    if( buf2 )
      buf += '\n\n' + buf2;

    ssh_close_connection( socket:soc );

  } else {

    if( ! defined_func( "ssh_shell_open" ) )
      exit( 0 );

    # nb: Only required here, ssh_login_or_reuse_connection() is handling these internally...
    user = kb_ssh_login();
    pass = kb_ssh_password();
    if( ! user || ! pass )
      exit( 0 );

    if( ! soc = open_sock_tcp( port ) )
      continue;

    if( ! sess = ssh_connect( socket:soc ) ) {
      close( soc );
      continue;
    }

    auth_successful = ssh_userauth( sess, login:NULL, password:NULL, privatekey:NULL, passphrase:NULL );

    # nb: ssh_userauth() is returning 0 on success but everything else like -1, 1 or NULL is an error
    # or failure. In the initial implementation of this code "if(ssh_userauth())" was used below to
    # cover all != 0 cases but the NULL case was missed which is now also checked below.
    if( isnull( auth_successful ) || auth_successful ) {
      close( soc );
      continue;
    }

    if( ! shell = ssh_shell_open( sess ) ) {
      close( soc );
      continue;
    }

    buf = ssh_read_from_shell( sess:sess, pattern:"User:", timeout:30, retry:10 );
    if( ! buf || "User:" >!< buf ) {
      close( soc );
      continue;
    }

    # nb: Depending on the size of the "show sysinfo" output we might get a few "--More-- or (q)uit".
    # This is the reason why we have four newlines in between both commands (initially there were
    # only two which caused some missing model detection).
    ssh_shell_write( sess, cmd:user + '\n' + pass + '\n' + 'show sysinfo\n\n\n\nshow inventory\n' );

    buf = ssh_read_from_shell( sess:sess, pattern:"PID", timeout:30, retry:10 );

    close( soc );
  }

  # Product Name..................................... Cisco Controller
  if( ! buf || buf !~ "Product Name[.]+ Cisco Controller" )
    exit( 0 );

  set_kb_item( name:"cisco/wlc/detected", value:TRUE );
  set_kb_item( name:"cisco/wlc/ssh-login/detected", value:TRUE );
  set_kb_item( name:"cisco/wlc/ssh-login/show_sysinfo_inventory", value:buf );
  set_kb_item( name:"cisco/wlc/ssh-login/port", value:port );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  version = "unknown";
  model   = "unknown";

  # Product Version.................................. 8.2.100.0
  # Product Version.................................. 8.5.182.0
  vers = eregmatch( pattern:'Product Version[.]+ ([0-9][^\r\n ]+)', string:buf );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    concluded = "    'show sysinfo' command response:   " + vers[0];
  }

  # PID: AIR-CTVM-K9,  VID: V01,  SN: <redacted>
  mod = eregmatch( pattern:"PID: ([^,]+),", string:buf );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
    if( concluded )
      concluded += '\n';
    concluded += "    'show inventory' command response: " + mod[0];
  }

  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/concluded", value:concluded );
  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/version", value:version );
  set_kb_item( name:"cisco/wlc/ssh-login/" + port + "/model", value:model );
}

exit( 0 );
