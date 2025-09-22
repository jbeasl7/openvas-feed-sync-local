# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103999");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2011-03-08 16:17:59 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Show System Characteristics");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("kb_2_sc.nasl", "gb_nist_win_oval_sys_char_generator.nasl");
  script_mandatory_keys("system_characteristics/created");

  script_tag(name:"summary", value:"Show OVAL System Characteristics if they have been previously gathered and are available
  in the Knowledge Base.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

if( get_kb_item( "SMB/WindowsVersion" ) ) {
  sc = get_kb_item( "nist_windows_system_characteristics" );
} else {
  sc = get_kb_item( "system_characteristics" );
}

if( sc ) {
  log_message( port:0, data:sc, proto:"OVAL-SC" );
}

exit( 0 );
