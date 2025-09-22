# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108350");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login_banner/available");

  script_tag(name:"summary", value:"SSH banner-based detection of a NetEx HyperIP virtual
  appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

#                            PRIVATE/PROPRIETARY/SECURE
#                       NO DISCLOSURE OUTSIDE THIS DOMAIN
#                          EXCEPT BY WRITTEN AGREEMENT.
#                    MUST BE SECURELY STORED WHEN NOT IN USE.
#                      UNAUTHORIZED ACCESS TO, OR MISUSE OF
#                       THIS SYSTEM OR DATA IS PROHIBITED.
#                   THIS SYSTEM MAY BE PERIODICALLY MONITORED
#                                AND/OR AUDITED.
#
#HyperIP 6.1.1 example.com 127.0.0.1 127.0.0.2
banner = ssh_get_login_banner( port:port );
if( ! banner || ! egrep( pattern:"^HyperIP", string:banner, icase:FALSE ) )
  exit( 0 );

version = "unknown";

vers = eregmatch( pattern:"HyperIP ([0-9.]+)", string:banner );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"hyperip/ssh-banner/" + port + "/concluded", value:vers[0] );
}

set_kb_item( name:"hyperip/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-banner/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-banner/port", value:port );
set_kb_item( name:"hyperip/ssh-banner/" + port + "/version", value:version );

exit( 0 );
