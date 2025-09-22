# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103941");
  script_version("2022-06-28T10:11:01+0000");
  script_name("File Checksums: Matches");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-28 10:11:01 +0000 (Tue, 28 Jun 2022)");
  script_tag(name:"creation_date", value:"2013-08-21 16:07:49 +0200 (Wed, 21 Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("Policy/policy_file_checksums.nasl");
  script_mandatory_keys("policy/file_checksums/started");

  script_tag(name:"summary", value:"List files with no checksum violation or error.");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

md5pass  = get_kb_list( "policy/file_checksums/md5_ok_list" );
sha1pass = get_kb_list( "policy/file_checksums/sha1_ok_list" );

if( md5pass || sha1pass ) {

  # Sort to not report changes on delta reports if just the order is different
  if( md5pass )  md5pass  = sort( md5pass );
  if( sha1pass ) sha1pass = sort( sha1pass );

  report  = 'The following file checksums match:\n\n';
  report += 'Filename|Result|Errorcode;\n';

  foreach pass( md5pass ) {
    report += pass + '\n';
  }
  foreach pass( sha1pass ) {
    report += pass + '\n';
  }
  log_message( port:0, data:report );
}

exit( 0 );
