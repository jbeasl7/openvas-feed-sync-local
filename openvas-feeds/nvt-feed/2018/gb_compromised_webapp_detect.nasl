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
  script_oid("1.3.6.1.4.1.25623.1.0.108459");
  script_version("2022-12-02T10:11:16+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-02 10:11:16 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2018-09-06 13:30:22 +0200 (Thu, 06 Sep 2018)");
  script_name("Compromised Web Application Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/compromised_webapp/detected");

  script_xref(name:"URL", value:"https://gwillem.gitlab.io/2018/08/30/magentocore.net_skimmer_most_aggressive_to_date/");

  script_tag(name:"summary", value:"This script reports if a web page of the remote host was compromised by known
  Skimmer / Malware code.");

  script_tag(name:"insight", value:"Currently the Indicator of compromise (IOC) of the following
  known Skimmer / Malware code is evaluated / reported:

  - MagentoCore skimmer");

  script_tag(name:"impact", value:"A compromised web page might have various impact depending on the deployed code. Please
  check the referenced links for more information on the impact of specific code.");

  script_tag(name:"solution", value:"Inspect all reported web pages / URLs and remove the related source code. Further analysis on entry points,
  possible additional deployed backdoors or user accounts and similar is required.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

# TODO: Add more possible IOCs

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

# nb: Currently set by webmirror.nasl only but Detection-VTs like sw_magento_detect.nasl could
# be extended if known additional URLs are known where the files are placed if those are not
# detected by webmirror.nasl.
compromisedList = get_kb_list( "www/" + host + "/" + port + "/content/compromised_webapp" );
if( ! compromisedList || ! is_array( compromisedList ) ) exit( 99 );

# Sort to not report changes on delta reports if just the order is different
compromisedList = sort( compromisedList );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach compromisedItem( compromisedList ) {

  info = split( compromisedItem, sep:"#----#", keep:FALSE );
  if( ! info ) continue; # nb: something went wrong...

  compPage = info[0];
  compCode = info[1];
  compInfo = info[2];

  if( ! compCode ) compInfo = "No source code currently collected";
  if( ! compInfo ) compInfo = "No information currently available";

  if( report ) report += '\n\n';

  report += "Compromised page on the target: " + compPage + '\n';
  report += "IOC source code: " + compCode + '\n';
  report += "Resource/link/further info: " + compInfo;
}

security_message( port:port, data:'The following Indicator of compromise (IOC) were found:\n\n' + report );
exit( 0 );
