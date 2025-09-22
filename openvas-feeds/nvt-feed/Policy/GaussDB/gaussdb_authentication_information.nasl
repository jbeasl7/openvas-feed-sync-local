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
  script_oid("1.3.6.1.4.1.25623.1.0.150259");
  script_version("2021-03-04T12:22:07+0000");
  script_tag(name:"last_modification", value:"2021-03-04 12:22:07 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-05-20 12:47:26 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB: Authentication Parameters");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Compliance");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"User", type:"entry", value:"SYS", id:1);
  script_add_preference(name:"Password", type:"password", value:"Changeme_123", id:2);
  script_add_preference(name:"IP", type:"entry", value:"127.0.0.1", id:3);
  script_add_preference(name:"Port", type:"entry", value:"1611", id:4);
  script_add_preference(name:"GSDB_HOME", type:"entry", value:"", id:5);
  script_add_preference(name:"GSDB_DATA", type:"entry", value:"", id:6);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The default administrator of GaussDB 100 is SYS and its default
  password is Changeme_123. To ensure information security, change the password of SYS as soon as
  possible.

  Enter credentials for using different user, password, ip or port for GaussDB Policy Controls.
  Enter values for GSDB_HOME and GSDB_DATA, if these variables should not be determined during the scan.");

  exit(0);
}

user = script_get_preference( "User", id:1 );
if( user != "" )
  set_kb_item( name:"Policy/gaussdb/user", value:user );
else
  set_kb_item( name:"Policy/gaussdb/user", value:"SYS" );

password = script_get_preference( "Password", id:2 );
if( password != "" )
  set_kb_item( name:"Policy/gaussdb/password", value:password );
else
  set_kb_item( name:"Policy/gaussdb/password", value:"Changeme_123" );

ip = script_get_preference( "IP", id:3 );
if( ip != "" )
  set_kb_item( name:"Policy/gaussdb/ip", value:ip );
else
  set_kb_item( name:"Policy/gaussdb/ip", value:"127.0.0.1" );

port = script_get_preference( "Port", id:4 );
if( port != "" )
  set_kb_item( name:"Policy/gaussdb/port", value:port );
else
  set_kb_item( name:"Policy/gaussdb/port", value:"1888" );

gsdb_home = script_get_preference( "GSDB_HOME", id:5 );
if( gsdb_home && gsdb_home != "" )
  set_kb_item( name:"Policy/gaussdb/gsdb_home", value:ereg_replace( string:gsdb_home, pattern:"/$", replace:"" ) );

gsdb_data = script_get_preference( "GSDB_DATA", id:6 );
if( gsdb_data && gsdb_data != "" )
  set_kb_item( name:"Policy/gaussdb/gsdb_data", value:ereg_replace( string:gsdb_data, pattern:"/$", replace:"" ) );

exit( 0 );