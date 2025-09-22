# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117185");
  script_version("2025-07-15T05:43:28+0000");
  script_tag(name:"last_modification", value:"2025-07-15 05:43:28 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"creation_date", value:"2021-01-27 06:47:49 +0000 (Wed, 27 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("sudo / sudoers Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.sudo.ws/");

  script_tag(name:"summary", value:"SSH login-based detection of sudo and various sudoers
  components.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/sudo$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

foreach full_path( full_path_list ) {

  if( ! full_path = chomp( full_path ) )
    continue;

  # nb:
  # - Older versions like Sudo 1.6.9p10 doesn't support "--version" but only the "-V" one
  # - Newer ones are supporting both so we're using "-V" here
  buf = ssh_cmd( socket:sock, cmd:full_path + " -V" );
  if( ! buf || "Sudo version " >!< buf )
    continue;

  sudo_version = "unknown";
  sudo_vers_concl = "";
  set_kb_item( name:"sudo/detected", value:TRUE );
  set_kb_item( name:"sudo/ssh-login/detected", value:TRUE );

  # Note: If sudo -V is called by the "root" user it will contain a lot of more
  # information like "Sudoers path: /etc/sudoers".
  #
  # Examples:
  #
  # Debian testing (trixie):
  # Sudo version 1.9.16p1
  # Sudoers policy plugin version 1.9.16p1
  # Sudoers file grammar version 50
  # Sudoers I/O plugin version 1.9.16p1
  # Sudoers audit plugin version 1.9.16p1
  #
  # Debian Bookworm:
  # Sudo version 1.9.13p3
  # Sudoers policy plugin version 1.9.13p3
  # Sudoers file grammar version 50
  # Sudoers I/O plugin version 1.9.13p3
  # Sudoers audit plugin version 1.9.13p3
  #
  # Debian testing (bullseye):
  # Sudo version 1.9.5p1
  # Sudoers policy plugin version 1.9.5p1
  # Sudoers file grammar version 48
  # Sudoers I/O plugin version 1.9.5p1
  # Sudoers audit plugin version 1.9.5p1
  #
  # Debian Stretch:
  # Sudo version 1.8.19p1
  # Sudoers policy plugin version 1.8.19p1
  # Sudoers file grammar version 45
  # Sudoers I/O plugin version 1.8.19p1
  #
  # Debian Jessie:
  # Sudo version 1.8.10p3
  # Sudoers policy plugin version 1.8.10p3
  # Sudoers file grammar version 43
  # Sudoers I/O plugin version 1.8.10p3
  #
  # Ubuntu 8.04 (only has the Sudo version line):
  # Sudo version 1.6.9p10
  #
  # CentOS 7:
  # Sudo version 1.8.23
  # Sudoers policy plugin version 1.8.23
  # Sudoers file grammar version 46
  # Sudoers I/O plugin version 1.8.23
  #
  # Fedora 33:
  # Sudo version 1.9.2
  # Sudoers policy plugin version 1.9.2
  # Sudoers file grammar version 48
  # Sudoers I/O plugin version 1.9.2
  # Sudoers audit plugin version 1.9.2

  sudo_vers = eregmatch( string:buf, pattern:"^Sudo version ([0-9.p]+)", icase:FALSE );
  if( sudo_vers[1] ) {
    sudo_version = sudo_vers[1];
    sudo_vers_concl = sudo_vers[0];
  }

  sudo_cpe = build_cpe( value:sudo_version, exp:"^([0-9.]+)(p[0-9]+)?", base:"cpe:/a:sudo_project:sudo:" );
  if( ! sudo_cpe )
    sudo_cpe = "cpe:/a:sudo_project:sudo";

  register_product( cpe:sudo_cpe, location:full_path, port:0, service:"ssh-login" );
  report = build_detection_report( app:"Sudo", version:sudo_version, install:full_path, cpe:sudo_cpe, concluded:sudo_vers_concl );

  sudoers_comps = egrep( string:buf, pattern:"^Sudoers .+ version ", icase:FALSE );
  if( sudoers_comps ) {
    split_comps = split( sudoers_comps, keep:FALSE );
    foreach split_comp( split_comps ) {
      comp_info = eregmatch( string:split_comp, pattern:"(Sudoers .+) version ([0-9.p]+)", icase:FALSE );
      if( ! comp_info )
        continue;

      comp_concl = comp_info[0];
      comp_name = comp_info[1];
      comp_vers = comp_info[2];
      comp_base_cpe = "cpe:/a:sudo_project:" + tolower( comp_name );
      comp_base_cpe = str_replace( string:comp_base_cpe, find:" ", replace:"_" );

      comp_cpe = build_cpe( value:comp_vers, exp:"^([0-9.]+)(p[0-9]+)?", base:comp_base_cpe + ":" );
      if( ! comp_cpe )
        comp_cpe = comp_base_cpe;

      register_product( cpe:comp_cpe, location:full_path, port:0, service:"ssh-login" );
      report += '\n\n';
      report += build_detection_report( app:comp_name, version:comp_vers, install:full_path, cpe:comp_cpe, concluded:comp_concl );
    }
  }

  log_message( port:0, data:report );
}

ssh_close_connection();
exit( 0 );
