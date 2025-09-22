# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108578");
  script_version("2024-03-08T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-03-08 05:05:30 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenSSH Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenSSH.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

port = kb_ssh_transport();

# nb: ssh_find_file() instead of ssh_find_bin() is used here so that we're able to use a regex
path_list = ssh_find_file( file_name:"/sshd?$", sock:sock, useregex:TRUE );
if( ! path_list || ! is_array( path_list ) )
  path_list = make_list();

# Add some common known file locations.
# nb: The sbin ones are added here as mlocate might not find these but the
# binaries are still accessible for version gathering in most situations.
known_exclusions = make_list(
  "/etc/ssh",
  "/usr/lib/apt/methods/ssh",
  "/etc/init.d/ssh",
  "/etc/default/ssh",
  "/etc/pam.d/sshd" );

known_locations = make_list(
  "/usr/bin/ssh",
  "/usr/local/bin/ssh",
  "/usr/sbin/sshd",
  "/usr/local/sbin/sshd" );

foreach known_location( known_locations ) {
  if( ! in_array( search:known_location, array:path_list, part_match:FALSE ) )
    path_list = make_list( path_list, known_location );
}

foreach path( path_list ) {

  path = chomp( path );
  if( ! path )
    continue;

  if( in_array( search:path, array:known_exclusions, part_match:FALSE ) )
    continue;

  # ssh -V examples:
  # OpenSSH_4.7p1 Debian-8ubuntu1, OpenSSL 0.9.8g 19 Oct 2007
  # OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
  # OpenSSH_7.2p2, OpenSSL 1.0.2k-fips  26 Jan 2017
  # OpenSSH_7.7, LibreSSL 2.7.2
  # OpenSSH_6.0p1 Debian-4+deb7u7, OpenSSL 1.0.1t  3 May 2016
  # OpenSSH_6.7p1 Debian-5+deb8u3, OpenSSL 1.0.1t  3 May 2016
  # OpenSSH_7.4p1 Debian-10+deb9u4, OpenSSL 1.0.2q  20 Nov 2018
  #
  # nb: sshd doesn't support a -V parameter but is printing out the same version pattern above with a prepended "sshd: illegal option -- V" and an appended "usage: sshd" message
  vers = ssh_get_bin_version( full_prog_name:path, sock:sock, version_argv:"-V", ver_pattern:'OpenSSH_([.a-zA-Z0-9]+)[- ]?[^\r\n]+' );
  if( vers[1] ) {
    version = vers[1];
    found = TRUE;

    if( "usage: sshd" >< vers[ max_index( vers ) - 1] )
      type = "Server";
    else
      type = "Client";

    set_kb_item( name:"openssh/ssh-login/" + port + "/installs", value:"0#---#" + path + "#---#" + version + "#---#" + vers[0] + "#---#" + type );
  }
}

if( found ) {
  set_kb_item( name:"openssh/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh-login/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh-login/port", value:port );
}

exit( 0 );
