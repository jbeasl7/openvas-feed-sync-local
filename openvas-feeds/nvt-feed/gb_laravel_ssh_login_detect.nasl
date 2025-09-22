# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135013");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-24 11:20:11 +0000 (Sat, 24 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Laravel Framework Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Laravel Framework.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

port = kb_ssh_transport();

paths = ssh_find_file( file_name: "/artisan$", useregex: TRUE, sock: sock );
if( ! paths ) {
  ssh_close_connection();
  exit( 0 );
}

foreach bin( paths ) {
  bin = chomp( bin );
  if( ! bin )
    continue;

  # Laravel Framework 5.5.50

  vers = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: " --version | cat", ver_pattern: "Laravel Framework ([0-9.]+)" );
  if( isnull( vers[1] ) )
    continue;

  version = tolower( vers[1] );

  set_kb_item( name: "laravel/detected", value: TRUE );
  set_kb_item( name: "laravel/ssh-login/detected", value: TRUE );
  set_kb_item( name: "laravel/ssh-login/port", value: port );
  set_kb_item( name: "laravel/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + version + "#---#" + vers[0] );
}

exit( 0 );
