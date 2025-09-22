# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108258");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-10-20 12:31:00 +0200 (Fri, 20 Oct 2017)");
  script_name("GNU Bash Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of GNU bash.

  The script logs in via SSH, searches for the executable 'bash' and queries the
  found executables via the command line option '--version'");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

binaries = ssh_find_file( file_name:"/bash$", useregex:TRUE, sock:sock );

foreach binary( binaries ) {

  binary = chomp( binary );
  if( ! binary )
    continue;

  version = ssh_get_bin_version( full_prog_name:binary, sock:sock, version_argv:"--version", ver_pattern:"GNU bash, version ([0-9.]+)" );

  if( version[1] ) {

    set_kb_item( name:"bash/linux/ver", value:version[1] );
    set_kb_item( name:"bash/linux/detected", value:TRUE );
    found = TRUE;

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:gnu:bash:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:gnu:bash";

    register_product( cpe:cpe, location:binary, port:0, service:"ssh-login" );

    log_message( data:build_detection_report( app:"GNU bash",
                                              version:version[1],
                                              install:binary,
                                              cpe:cpe,
                                              concluded:version[0] ) );
  }
}

# Fallback for the Shellshock VTs as a last resort if the detection above doesn't work
# against some special devices / systems.
if( ! found ) {
  result = ssh_cmd( socket:sock, cmd:"bash --version", nosh:TRUE );
  if( "GNU bash" >< result ) {

    version = "unknown";
    install = "unknown";
    set_kb_item( name:"bash/linux/detected", value:TRUE );

    vers = eregmatch( pattern:"GNU bash, version ([0-9.]+)", string:result );
    if( vers[1] ) {
      version = vers[1];
      set_kb_item( name:"bash/linux/ver", value:version );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:gnu:bash:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:gnu:bash";

    register_product( cpe:cpe, location:install, port:0, service:"ssh-login" );

    log_message( data:build_detection_report( app:"GNU bash",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ) );

  }
}

ssh_close_connection();
exit( 0 );
