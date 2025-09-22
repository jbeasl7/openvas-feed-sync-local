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
  script_oid("1.3.6.1.4.1.25623.1.0.108449");
  script_version("2022-07-27T10:11:28+0000");
  script_tag(name:"last_modification", value:"2022-07-27 10:11:28 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-07-05 08:03:26 +0200 (Thu, 05 Jul 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Hostname Determination Reporting");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_family("Service detection");

  script_tag(name:"summary", value:"The script reports information on how the hostname of the target
  was determined.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

# Available since GVM-10 / git commit 4ba1a59
if( ! defined_func( "get_host_names" ) || ! defined_func( "get_host_name_source" ) ) exit( 0 );

SCRIPT_DESC = "Hostname Determination Reporting";
ip          = get_host_ip();
hostnames   = get_host_names();
report      = ""; # nb: To make openvas-nasl-lint happy...

# Sort to not report changes on delta reports if just the order is different
hostnames = sort( hostnames );

foreach hostname( hostnames ) {
  source = get_host_name_source( hostname:hostname );
  register_host_detail( name:"hostname_determination", value:ip + "," + hostname + "," + source, desc:SCRIPT_DESC );
  report += '\n' + hostname + "|" + source;
}

if( strlen( report ) > 0 ) {
  report = "Hostname determination for IP " + ip + ':\n\nHostname|Source' + report;
  log_message( port:0, data:report );
}

exit( 0 );