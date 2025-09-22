# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.901025");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dovecot Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Dovecot.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

paths = ssh_find_bin( prog_name:"dovecot", sock:sock );
foreach dovecotbin( paths ) {

  dovecotbin = chomp( dovecotbin );
  if( ! dovecotbin ) continue;

  #e.g. 2.2.27 (c0f36b0) or 2.2.22.rc1 (fe789d2)
  dovecotVer = ssh_get_bin_version( full_prog_name:dovecotbin, sock:sock, version_argv:"--version", ver_pattern:"^([0-9.]{4,}(rc[0-9]+)?)\s*(\([^)]+\))?" );
  if( ! isnull( dovecotVer[1] ) ) {
    set_kb_item( name:"dovecot/detected", value:TRUE );
    set_kb_item( name:"dovecot/ssh-login/detected", value:TRUE );

    #Format used in gb_dovecot_consolidation.nasl is:
    #Detection-Name#--#service#--#port#--#location#--#version#--#concluded
    set_kb_item( name:"dovecot/detection-info", value:"SSH login#--#ssh-login#--#0#--#" + dovecotbin + "#--#" + dovecotVer[1] + "#--#" + dovecotVer[0] );
  }
}

ssh_close_connection();
exit( 0 );
