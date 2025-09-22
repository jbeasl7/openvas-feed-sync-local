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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113225");
  script_version("2022-03-28T10:48:38+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:48:38 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ecessa ShieldLink / PowerLink Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ecessa_shieldlink_snmp_detect.nasl", "gb_ecessa_shieldlink_telnet_detect.nasl");
  script_mandatory_keys("ecessa_link/detected");

  script_tag(name:"summary", value:"Consolidation of Ecessa ShieldLink or PowerLink detections.");

  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/");
  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/product_comp_shieldlink/");

  exit(0);
}

include( "host_details.inc" );
include( "cpe.inc" );

if( get_kb_item( "ecessa_shieldlink/detected" ) ) {
  kb_base = "ecessa_shieldlink";
  CPE = "cpe:/h:ecessa:shieldlink:";
  app_name = "Ecessa ShieldLink";
}
else if( get_kb_item( "ecessa_powerlink/detected" ) ) {
  kb_base = "ecessa_powerlink";
  CPE = "cpe:/h:ecessa:powerlink";
  app_name = "Ecessa PowerLink";
}
else {
  exit( 0 );
}

version = "unknown";
extra = 'Detection methods:\r\n';
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach proto ( make_list( "snmp", "telnet" ) ) {

  if( version == "unknown" ) {
    vers = get_kb_item( kb_base + "/" + proto + "/version" );
    if( ! isnull( vers ) && vers != "unknown" ) {
      version = vers;
    }
  }

  port = get_kb_item( kb_base + "/" + proto + "/port" );
  if( ! isnull( port ) ) {
    extra += '\r\n' + toupper(proto) + " at port: " + port;
  }

  proto_concluded = get_kb_item( kb_base + "/" + proto + "/concluded" );
  if( ! isnull( proto_concluded ) ) {
    concluded += '\r\n' + toupper(proto) + ' concluded from:\r\n' + proto_concluded;
  }
}

register_and_report_cpe( app: app_name,
                         ver: version,
                         concluded: concluded,
                         base: CPE,
                         expr: '([0-9.]+)',
                         regPort: 0,
                         extra: extra );

exit( 0 );
