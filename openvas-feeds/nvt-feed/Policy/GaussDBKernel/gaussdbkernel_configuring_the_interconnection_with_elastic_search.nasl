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
  script_oid("1.3.6.1.4.1.25623.1.0.150442");
  script_version("2020-11-20T12:35:19+0000");
  script_tag(name:"last_modification", value:"2020-11-20 12:35:19 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB Kernel: Configuring the Interconnection with Elastic Search");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_gaussdb_kernel_ssh_login_detect.nasl", "gaussdbkernel_authentication_information.nasl");
  script_mandatory_keys("huawei/gaussdb_kernel/detected", "Compliance/Launch");

  script_tag(name:"summary", value:"Unified audit sends audit logs to the third-party Elastic Search system for log
analysis and processing. You are advised to configure the interconnection with
Elastic Search.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "SELECT name,setting FROM pg_settings WHERE name = 'use_elastic_search';";
title = "Configuring the Interconnection with Elastic Search";
solution = "Change the IP address to the listening IP address of the Elastic Search service. The
default listening port of Elastic Search is 9200.
gs_guc reload -Z coordinator -N all -I all -c 'use_elastic_search=on'
gs_guc reload -Z coordinator -N all -I all -c 'elastic_search_ip_addr = 'https:\/\/*.*.*.*'";
default = "on";
test_type = "SQL_Query";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if ( ! value = policy_gsql_cmd( socket:sock, query:cmd, db_type:"gaussdbkernel" ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "SQL command did not return anything";
}else if ( ! elastic_search_ip_addr = policy_gsql_cmd( socket:sock, query:"SELECT name,setting FROM pg_settings WHERE name = 'elastic_search_ip_addr';", db_type:"gaussdbkernel" ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "No elastic_search_ip_addr found";
}else if ( value =~ "failed to connect" || elastic_search_ip_addr =~ "failed to connect" ) {
  compliant = "incomplete";
  value = "error";
  comment = "No connection to database";
}else{
  value = ereg_replace( string:chomp( value ), pattern:"^\s+", replace:"" );
  setting = eregmatch( string:value, pattern:"use_elastic_search\s+\|\s+(.+)" );
  if( ! setting[1] ){
    compliant = "incomplete";
    comment = "Can not determine setting.";
  }else{
    compliant = policy_setting_exact_match( value:setting[1], set_point:default );
    comment = elastic_search_ip_addr;
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
