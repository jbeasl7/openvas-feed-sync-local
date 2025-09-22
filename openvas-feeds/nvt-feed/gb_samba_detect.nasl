# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800403");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Samba Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Samba.

  The script logs in via SSH, searches for executable 'smbd' and
  queries the found executables via command line option '-V'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit(0);

smbName = ssh_find_file( file_name:"/smbd$", useregex:TRUE, sock:sock );

foreach executableFile( smbName ) {

  executableFile = chomp( executableFile );
  if(!executableFile)
    continue;

  smbVer = ssh_get_bin_version( full_prog_name:executableFile, version_argv:"-V", ver_pattern:"Version (.*)", sock:sock );
  smbVer = split( smbVer[1], "\n", keep:FALSE );

  if( ! isnull( smbVer[0] ) ) {

    set_kb_item( name:"Samba/Version", value:smbVer[0] );
    set_kb_item( name:"samba/ssh/detected", value:TRUE );

    # nb: Used together with smb_nativelanman.nasl if the VT needs an exposed version.
    set_kb_item( name:"samba/smb_or_ssh/detected", value:TRUE );

    # nb: See https://www.samba.org/samba/samba/history/ for some of the possible versions
    cpe = build_cpe( value:smbVer[0], exp:"([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?", base:"cpe:/a:samba:samba:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:samba:samba";

    register_product( cpe:cpe, location:executableFile, port:0 );

    log_message( data:build_detection_report( app:"Samba",
                                              version:smbVer[0],
                                              install:executableFile,
                                              cpe:cpe,
                                              concluded:smbVer[max_index(smbVer)-1] ) );
  }
}

ssh_close_connection();

exit( 0 );
