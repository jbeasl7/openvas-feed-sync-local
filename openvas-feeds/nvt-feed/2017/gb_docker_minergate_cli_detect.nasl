# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140237");
  script_version("2021-04-21T07:59:45+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 07:59:45 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-04-06 11:47:35 +0200 (Thu, 06 Apr 2017)");
  script_name("Docker is running `minergate-cli` Container");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Malware");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/container/present");

  script_tag(name:"summary", value:"The remote docker is running one or more `minergate-cli`
  container.");

  script_tag(name:"vuldetect", value:"Check running containers.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.");

  script_xref(name:"URL", value:"https://hub.docker.com/r/minecoins/minergate-cli/");

  exit(0);
}

include("docker.inc");

if( ! c = docker_get_running_containers() )
  exit( 0 );

foreach container( c ) {
  if( container["image"] == "minecoins/minergate-cli" ) {
    ac += "ID:    " + docker_truncate_id( container["id"] ) + '\n' +
          "Name:  " + container["name"] + '\n' +
          "Image: " + container["image"] + '\n\n';
  }
}

if( ac ) {
  report = 'The following `minecoins/minergate-cli` docker containers are running on the remote host:\n\n' + ac;
  security_message( port:0, data:chomp( report ) );
}

exit( 0 );