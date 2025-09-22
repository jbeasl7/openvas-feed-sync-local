# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806084");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-13 12:00:27 +0530 (Tue, 13 Oct 2015)");
  script_name("GNU Assembler Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of GNU Assembler.

  The script logs in via ssh, searches for executable 'as' and queries the
  found executables via command line option '-v'");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

binary_list = ssh_find_file( file_name:"/as$", useregex:TRUE, sock:sock );
if( ! binary_list ) {
  ssh_close_connection();
  exit( 0 );
}

foreach binary_name( binary_list ) {

  binary_name = chomp( binary_name );
  if( ! binary_name )
    continue;

  # GNU assembler (GNU Binutils for Debian) 2.35
  # GNU assembler (GNU Binutils for Ubuntu) 2.18.0.20080103
  # GNU assembler version 2.25.1-22.base.h43
  # GNU assembler version 2.26.1-1.fc24
  # GNU assembler (GNU Binutils; SUSE Linux Enterprise 11) 2.24.0.20140403-3
  # nb: Don't use -V or -v as version parameter because "as" won't exit for these parameters,
  # is waiting for input and will write a "a.out" once the timeout of 30 seconds was reached.
  vers = ssh_get_bin_version( full_prog_name:binary_name, sock:sock, version_argv:"--version", ver_pattern:"GNU assembler (version|\([^)]+\)) ([0-9.]+)" );
  if( vers[2] ) {

    set_kb_item( name:"gnu/assembler/detected", value:TRUE );

    # nb: "as" is part of GNU Binutils and has the same version
    if( egrep( string:vers[0], pattern:"\(GNU Binutils[^)]*\)", icase:FALSE ) ) {
      set_kb_item( name:"gnu/binutils/binaries/list", value:binary_name + "#----#" + vers[2] + "#----#" + vers[0] );
      set_kb_item( name:"gnu/binutils/binaries/detected", value:TRUE );
    }

    cpe = build_cpe( value:vers[2], exp:"^([0-9.]+)", base:"cpe:/a:gnu:assembler:" );
    if( ! cpe )
      cpe = "cpe:/a:gnu:assembler";

    register_product( cpe:cpe, location:binary_name, port:0, service:"ssh-login" );

    log_message( data:build_detection_report( app:"GNU Assembler",
                                              version:vers[2],
                                              install:binary_name,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                 port:0 );
  }
}

ssh_close_connection();
exit( 0 );
