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
  script_oid("1.3.6.1.4.1.25623.1.0.113287");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-11-06 13:53:47 +0200 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:11:00 +0000 (Mon, 29 Aug 2022)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-2126", "CVE-2016-2123");

  script_name("Samba >= 4.0.0, <= 4.5.2 Multiple Privilege Escalation Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2016-2126: Samba is prone to privilege elevation due to
  incorrect handling of the PAC (Privilege Attribute Certificate) checksum. A remote, authenticated,
  attacker can cause the winbindd process to creash using a legitimate Kerberos ticket. A local
  service with access to the winbindd privileged pipe can cause winbindd to cache elevated access
  permissions.

  - CVE-2016-2123: The Samba routine ndr_pull_dnsp_name contains an integer wrap problem, leading to
  an attacker-controlled memory overwrite. ndr_pull_dnsp_name parses data from the Samba Active
  Directory ldb database. Any user who can write to the dnsRecord attribute over LDAP can trigger this
  memory corruption.

  By default, all authenticated LDAP users can write to the dnsRecord attribute on new DNS objects.
  This makes the defect a remote privilege escalation.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  gain additional access rights.");

  script_tag(name:"affected", value:"Samba versions 4.0.0 through 4.3.12, 4.4.0 through 4.4.7 and
  4.5.0 through 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.3.13, 4.4.8 or 4.5.3 respectively.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2126.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94994");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2123.html");

  exit(0);
}

CPE = "cpe:/a:samba:samba";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.3.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.13", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.5.0", test_version2: "4.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );