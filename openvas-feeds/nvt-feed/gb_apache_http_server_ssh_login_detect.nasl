# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117233");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-02-25 11:11:24 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache HTTP Server Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of the Apache HTTP Server.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

# nb: On package based installs the file are placed in /usr/sbin which isn't necessarily
# indexed by mlocate so we're just adding the files here to be sure to catch them. Even
# if the binary is located in /usr/sbin we can call the -v command as an unprivileged user.
full_path_list = make_list( "/usr/sbin/apache2", "/usr/sbin/apache", "/usr/sbin/httpd" );

# nb:
# - All tested rpm based systems (SLES 15, CentOS 7, EulerOS 2.0 SP9) seem to use "httpd"
#   for the package manager based install.
# - All tested deb based systems (Ubuntu 20.04, Ubuntu 8.04, Debian 8.0 and Debian 9.0)
#   seem to use "apache2" for the package manager based install.
found_path_list = ssh_find_file( file_name:"/(httpd|apache2?)$", sock:sock, useregex:TRUE );
if( found_path_list ) {

  # nb: Some special handling because ssh_find_file() is currently returning the binaries
  # with trailing newlines and making the list "unique" wouldn't work in this case.
  foreach found_path( found_path_list ) {
    found_path = chomp( found_path );
    if( ! found_path )
      continue;

    full_path_list = make_list_unique( full_path_list, found_path );
  }
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  # nb: BusyBox is also providing a "httpd" binary:
  # https://busybox.net/downloads/BusyBox.html#httpd
  # and if we're calling this via the "-v" parameter below we would start a HTTP server on port 80
  # (if the scan was running as root and no other service listed on that port yet).
  # Initially the check was made with the 'httpd --help' command,
  # but on the other hand this would start the server in some cases
  if( full_path =~ "/httpd$" ) {
    check = ssh_cmd( socket:sock, cmd:"strings " + full_path );

    # e.g. (the "Verbose" part has/had tabs):
    # BusyBox v1.36.1 (2023-11-07 18:53:09 UTC) multi-call binary.
    # *snip*
    # Listen for incoming HTTP requests
    # *snip*
    #   -v[v]   Verbose
    #
    # nb: We're using a few variants from the above to catch possible different variants of the help banner
    if( ( "BusyBox " >< check && "Listen for incoming HTTP requests" >< check ) ||
        ( "BusyBox " >< check && check =~ "\s+-v\[v\]\s+Verbose" ) ||
        ( "Listen for incoming HTTP requests" >< check && check =~ "\s+-v\[v\]\s+Verbose" )
      ) {
      continue;
    }
  }

  # Server version: Apache/2.4.43 (Linux/SUSE) -> SLES 15
  # Server version: Apache/2.4.41 (Ubuntu) -> Ubuntu 20.04
  # Server version: Apache/2.4.6 (CentOS) -> CentOS 7
  # Server version: Apache/2.4.34 (Unix) -> EulerOS 2.0 SP9
  # Server version: Apache/2.2.8 (Ubuntu) -> Ubuntu 8.04
  # Server version: Apache/2.4.10 (Debian) -> Debian 8
  # Server version: Apache/2.4.25 (Debian) -> Debian 9
  vers = ssh_get_bin_version( full_prog_name:full_path, sock:sock, version_argv:"-v", ver_pattern:"Server version\s*:\s*Apache/([0-9.]+(-(alpha|beta))?)" );
  if( ! vers || ! vers[1] )
    continue;

  version = vers[1];
  concluded = vers[max_index(vers) - 1];

  set_kb_item( name:"apache/http_server/detected", value:TRUE );
  set_kb_item( name:"apache/http_server/ssh-login/detected", value:TRUE );
  # nb: "#---##---#" is expected below as we don't have a "Concluded URL" like defined by the HTTP Detection-VT.
  set_kb_item( name:"apache/http_server/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---##---#" );
}

ssh_close_connection();
exit( 0 );
