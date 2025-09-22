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
  script_oid("1.3.6.1.4.1.25623.1.0.112689");
  script_version("2021-07-20T06:19:26+0000");
  script_tag(name:"last_modification", value:"2021-07-20 06:19:26 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-15 09:53:11 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Huawei GaussDB Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei GaussDB.");

  script_xref(name:"URL", value:"https://e.huawei.com/en/solutions/cloud-computing/big-data/gaussdb-distributed-database");

  exit(0);
}

include( "ssh_func.inc" );
include( "host_details.inc" );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();

# nb: zengine is the database server program, zsql is the client program. Normally both should exist on
# a default setup but we still want to try the client program if the database server program wasn't found.
# The idea is basically to save the install path into an array as the array key and the version into the
# array value so that we're not reporting multiple installations for a single one where both binaries are
# accessible.
bins = ssh_find_file( file_name: "/(zengine|zsql)$", useregex: TRUE, sock: sock );
if( ! bins ) {
  ssh_close_connection();
  exit( 0 );
}

found = FALSE;
found_installs = make_array();
ver_pattern = "^(Zenith-)?Gauss(DB[-_])?([0-9A-Z]+)[-_]([A-Z]+[-_])?([A-Z0-9.]+) ?(Release [0-9a-z]+)?";

foreach bin( bins ) {

  # Used to not include the export call below in the install path reporting.
  ld_bin = bin;

  # We need to gather the base path so that we can use it in the array as explained above.
  # In addition on some setups the LD_LIBRARY_PATH isn't configured correctly causing the a
  # failed call of the binary. The path will passed to the get_bin_version below so that we're
  # still able to gather the version info.
  base_path = ereg_replace( string: bin, pattern: "(/s?bin/(zengine|zsql))$", replace: "" );

  # nb: Don't append a wrong base_path (including the binary or similar) to the LD_LIBRARY_PATH.
  if( base_path !~ "/(zengine|zsql)$" )
    ld_bin = 'export LD_LIBRARY_PATH="' + base_path + '/lib":"' + base_path + '/add-ons":$LD_LIBRARY_PATH; ' + bin;

  # GaussDB-100-V300R001C00SPC200B157 Release 4167676
  # GaussDB_100_1.0.1.SPC2.B003 Release 3ae9d6c
  # GaussDB_T_1.0.2.B303 Release cfa19bd
  # Zenith-Gauss100-OLTP-V300R001C00B300 Release
  # Zenith-Gauss100-OLTP-V300R001C00SPC100B216 Release 009e84d
  vers = ssh_get_bin_version( full_prog_name: ld_bin, sock: sock, version_argv: "-v", ver_pattern: ver_pattern ); # nb: zsql supports -version but zengine only -v
  if( ! vers )
    continue;

  # nb: As we have some optional pattern in the version regex the get_bin_version()
  # function is returning a list of variable length (e.g. vers[6] below might contain
  # the Release string OR the full "concluded" string). Working around this by using
  # an eregmatch here.
  vers = eregmatch( pattern: ver_pattern, string: vers[0] );
  if( ! isnull( vers[5] ) ) {

    version = vers[5];

    # nb: Avoid multiple reports for the same installation. There might be situations
    # like /usr/local/bin/zengine and /usr/local/bin/zsql which have the same version
    # but are different installations but we can't detect something like that at all.
    bin_path = ereg_replace( string: bin, pattern: "(/(zengine|zsql))$", replace: "" );
    if( found_installs[bin_path] && found_installs[bin_path] == version )
      continue;

    type = "unknown";
    model = "unknown";
    build = "unknown";
    release = "unknown";

    found_installs[bin_path] = version;

    if( ! isnull( vers[3] ) )
      type = vers[3];

    if( ! isnull( vers[1] ) )
      model = vers[1];

    # Separate the internal build number from the version
    if( build_match = eregmatch( pattern: "\.?B([0-9]{3})$", string: version ) ) {
      version = ereg_replace( pattern: build_match[0], string: version, replace: "" );
      build = build_match[1];
    }

    if( ! isnull( vers[6] ) )
      release = vers[6];

    found = TRUE;

    set_kb_item( name: "huawei/gaussdb/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + vers[0] + "#---#" + version + "#---#" + type + "#---#" + model + "#---#" + build + "#---#" + release );
  }
}

if( found ) {
  set_kb_item( name: "huawei/gaussdb/detected", value: TRUE );
  set_kb_item( name: "huawei/gaussdb/port", value: port );
}

ssh_close_connection();

exit( 0 );