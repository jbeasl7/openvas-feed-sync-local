# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108973");
  script_version("2021-07-20T12:03:58+0000");
  script_tag(name:"last_modification", value:"2021-07-20 12:03:58 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-10-26 07:21:21 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Huawei openGauss Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei openGauss.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

# nb: See note below
if( get_kb_item( "ssh/login/gaussdb_gsql_bins/" + port + "/not_found" ) ) {
  ssh_close_connection();
  exit( 0 );
}

if( get_kb_item( "ssh/login/gaussdb_gsql_bins/" + port + "/found" ) ) {
  bins = get_kb_list( "ssh/login/gaussdb_gsql_bins/" + port + "/locations" );
  # nb: Shouldn't happen but we're checking it anyway just to be sure...
  if( ! bins ) {
    ssh_close_connection();
    exit( 0 );
  }
} else {
  # nb: gaussdb is the database server program, gsql is the client program. Normally both should
  # exist on a default setup but we still want to try the client program if the database server
  # program wasn't found. The idea is basically to save the install path into an array as the array
  # key and the version into the array value so that we're not reporting multiple installations for
  # a single one where both binaries are accessible.
  bins = ssh_find_file( file_name:"/(gaussdb|gsql)$", useregex:TRUE, sock:sock );
  if( ! bins ) {
    ssh_close_connection();
    # nb: See note below
    set_kb_item( name:"ssh/login/gaussdb_gsql_bins/not_found", value:TRUE );
    set_kb_item( name:"ssh/login/gaussdb_gsql_bins/" + port + "/not_found", value:TRUE );
    exit( 0 );
  }
}

found = FALSE;
found_installs = make_array();

foreach bin( bins ) {

  # nb: As gb_huawei_gaussdb_kernel_ssh_login_detect.nasl and gb_huawei_opengauss_ssh_login_detect.nasl
  # are (at least currently) checking for the same two files gaussdb and gsql. To save a few SSH
  # requests the info below is shared across both VTs.
  set_kb_item( name:"ssh/login/gaussdb_gsql_bins/found", value:TRUE );
  set_kb_item( name:"ssh/login/gaussdb_gsql_bins/" + port + "/found", value:TRUE );
  set_kb_item( name:"ssh/login/gaussdb_gsql_bins/" + port + "/locations", value:bin );

  # Used to not include the export call below in the install path reporting.
  ld_bin = bin;

  # We need to gather the base path so that we can use it in the array as explained above.
  # In addition on some setups the LD_LIBRARY_PATH isn't configured correctly causing the a
  # failed call of the binary. The path will passed to the get_bin_version below so that we're
  # still able to gather the version info.
  base_path = ereg_replace( string:bin, pattern:"(/s?bin/(gaussdb|gsql))$", replace:"" );

  # nb: Don't append a wrong base_path (including the binary or similar) to the LD_LIBRARY_PATH.
  if( base_path !~ "/(gaussdb|gsql)$" )
    ld_bin = 'export LD_LIBRARY_PATH="' + base_path + '/lib":$LD_LIBRARY_PATH; ' + bin;

  # gaussdb (openGauss 1.0.0 build 0bd0ce80) compiled at 2020-06-30 18:19:27 commit 0 last mr
  # gsql (openGauss 1.0.0 build 0bd0ce80) compiled at 2020-06-30 18:19:27 commit 0 last mr
  vers = ssh_get_bin_version( full_prog_name:ld_bin, sock:sock, version_argv:"-V", ver_pattern:"\(openGauss ([VRCHPS0-9.]+)" );
  if( ! vers || ! vers[1] )
    continue;

  version = vers[1];

  # nb: Avoid multiple reports for the same installation. There might be situations
  # like /usr/local/bin/gaussdb and /usr/local/bin/gsql which have the same version
  # but are different installations but we can't detect something like that at all.
  bin_path = ereg_replace( string:bin, pattern:"(/(gaussdb|gsql))$", replace:"" );
  if( found_installs[bin_path] && found_installs[bin_path] == version )
    continue;

  found_installs[bin_path] = version;
  build = "unknown";

  if( build_match = eregmatch( pattern:"build ([^)]+)\)", string:vers[2] ) )
    build = build_match[1];

  found = TRUE;

  set_kb_item( name:"huawei/opengauss/ssh-login/" + port + "/installs", value:"0#---#" + bin + "#---#" + vers[2] + "#---#" + version + "#---#" + build );
}

if( found ) {
  set_kb_item( name:"huawei/opengauss/detected", value:TRUE );
  set_kb_item( name:"huawei/opengauss/port", value:port );
}

ssh_close_connection();

exit( 0 );