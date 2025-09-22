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
  script_oid("1.3.6.1.4.1.25623.1.0.113133");
  script_version("2021-06-22T11:00:29+0000");
  script_tag(name:"last_modification", value:"2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-03-14 11:45:55 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 14:54:00 +0000 (Wed, 09 Sep 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1050", "CVE-2018-1057");

  script_name("Samba 4.x Multiple Vulnerabilities (CVE-2018-1050, CVE-2018-1057)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exist two vulnerabilities:

  - CVE-2018-1050: Samba is vulnerable to a denial of service attack when the RPC spoolss service is
  configured to be run as an external daemon. Missing input sanitization checks on some of the input
  parameters to spoolss RPC calls could cause the print spooler service to crash.

  - CVE-2018-1057: On a Samba AD DC the LDAP server in Samba incorrectly validates permissions to
  modify passwords over LDAP allowing authenticated users to change any other users' passwords,
  including administrative users and privileged service accounts (eg Domain Controllers).");

  script_tag(name:"impact", value:"Successful exploitation would result in effects ranging from
  Denial of Service to Privilege Escalation, eventually allowing an attacker to gain full control
  over the target system.");

  script_tag(name:"affected", value:"Samba 4.x.x before 4.5.16, 4.6.x before 4.6.14 and 4.7.x before
  4.7.6.");

  script_tag(name:"solution", value:"Update to version 4.5.16, 4.6.14 or 4.7.6 respectively.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-1050.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-1057.html");

  exit(0);
}

CPE = "cpe:/a:samba:samba";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_in_range( version: vers, test_version: "4.0.0", test_version2: "4.5.15" ) ) {
  fixed_ver = "4.5.16";
}

if( version_in_range( version: vers, test_version: "4.6.0", test_version2: "4.6.13" ) ) {
  fixed_ver = "4.6.14";
}

if( version_in_range( version: vers, test_version: "4.7.0", test_version2: "4.7.5" ) ) {
  fixed_ver = "4.7.6";
}

if( fixed_ver ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: fixed_ver, install_path: loc );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );