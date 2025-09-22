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
  script_oid("1.3.6.1.4.1.25623.1.0.810980");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2017-5135");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-19 17:59:31 +0530 (Fri, 19 May 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Technicolor DPC3928SL Authentication Bypass Vulnerability (SNMP)");

  script_tag(name:"summary", value:"Technicolor DPC3928SL devices are prone to an SNMP
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted SNMP authentication request
  and check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"The flaw is due to the value placed in the
  community string field is not handled properly by the snmp agent in different
  devices (usually cable modems).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to bypass certain security restrictions and perform unauthorized
  actions like write in the MIB etc.");

  script_tag(name:"affected", value:"Technicolor DPC3928SL firmware version
  D3928SL-P15-13-A386-c3420r55105-160127a is vulnerable, other devices are also
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://stringbleed.github.io");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98092");
  script_xref(name:"URL", value:"https://www.reddit.com/r/netsec/comments/67qt6u/cve_20175135_snmp_authentication_bypass");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("snmp_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("snmp_func.inc");
include("misc_func.inc");

port = snmp_get_port( default:161 );

if( get_kb_item( "SNMP/" + port + "/v12c/all_communities" ) )
  exit( 0 ); # nb: For devices which are accepting random communities

vt_strings = get_vt_strings();

# Passing community string, any string integer value works
community = vt_strings["default"];

if (ret = snmp_get( port:port, oid:"1.3.6.1.2.1.1.1.0", version:2, community:community ) ) {
  report = 'Result of the system description query with the community "' + community + '":\n\n' + ret;
  security_message( port:port, data:report, proto:"udp" );
  exit( 0 );
}

exit( 99 );
