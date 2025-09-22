# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103592");
  script_version("2021-07-15T11:48:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-15 11:48:46 +0000 (Thu, 15 Jul 2021)");
  script_tag(name:"creation_date", value:"2012-10-25 10:12:52 +0200 (Thu, 25 Oct 2012)");
  script_name("PHP Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of PHP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

paths = ssh_find_file( file_name:"/php(-cli|[578](\.[0-9])?)?$", sock:sock, useregex:TRUE );
if( ! paths ) {
  ssh_close_connection();
  exit( 0 );
}

foreach path( paths ) {

  path = chomp( path );
  if( ! path )
    continue;

  # nb: Just a symlink on Debian systems to e.g. /usr/bin/php5 or /usr/bin/php7.0
  if( path == "/etc/alternatives/php" )
    continue;

  # PHP 5.6.30-0+deb8u1 (cli) (built: Feb  8 2017 08:50:21)
  # PHP 7.0.19-1 (cli) (built: May 11 2017 14:04:47) ( NTS )
  # PHP 7.4.3 (cli) (built: Jul  5 2021 15:13:35) ( NTS )
  vers = ssh_get_bin_version( full_prog_name:path, sock:sock, version_argv:"-vn", ver_pattern:"PHP ([^ ]+)" );
  if( ! vers[1] || vers[1] !~ "^[0-9.]{3,}" || "The PHP Group" >< vers[0] )
    continue;

  set_kb_item( name:"php/detected", value:TRUE );
  set_kb_item( name:"php/ssh-login/detected", value:TRUE );

  cpe = build_cpe( value:vers[1], exp:"([0-9.]+)", base:"cpe:/a:php:php:" );
  if( ! cpe )
    cpe = "cpe:/a:php:php";

  register_product( cpe:cpe, location:path, port:0, service:"ssh-login" );

  log_message( data:build_detection_report( app:"PHP",
                                            version:vers[1],
                                            install:path,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:0 );
}

exit( 0 );