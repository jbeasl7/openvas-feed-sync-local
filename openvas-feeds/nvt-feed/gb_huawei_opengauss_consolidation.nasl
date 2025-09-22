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
  script_oid("1.3.6.1.4.1.25623.1.0.108974");
  script_version("2020-10-27T08:26:53+0000");
  script_tag(name:"last_modification", value:"2020-10-27 08:26:53 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-26 07:21:21 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Huawei openGauss Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_huawei_opengauss_ssh_login_detect.nasl");
  script_mandatory_keys("huawei/opengauss/detected");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"Consolidation of Huawei openGauss detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "huawei/opengauss/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login" ) ) {

  install_list = get_kb_list( "huawei/opengauss/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );

    port    = infos[0];
    install = infos[1];
    concl   = infos[2];
    version = infos[3];
    build   = infos[4];
    extra   = "";

    cpe = build_cpe( value:tolower( version ), exp:"^([vrchps0-9.]+)", base:"cpe:/a:huawei:opengauss:" );
    if( ! cpe )
      cpe = "cpe:/a:huawei:opengauss";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( build != "unknown" && strlen( build ) == 8 )
      extra += "Internal build: " + build;

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Huawei openGauss",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl,
                                      extra:extra );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
