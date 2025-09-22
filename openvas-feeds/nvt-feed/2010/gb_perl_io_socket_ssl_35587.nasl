# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:io-socket-ssl:io-socket-ssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100674");
  script_version("2022-05-02T09:35:37+0000");
  script_cve_id("CVE-2009-3024");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
  script_name("Perl IO::Socket::SSL 'verify_hostname_of_cert()' Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_perl_modules_ssh_login_detect.nasl");
  script_mandatory_keys("perl/ssh-login/modules/io_socket_ssl/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35587");
  script_xref(name:"URL", value:"http://search.cpan.org/dist/IO-Socket-SSL/");
  script_xref(name:"URL", value:"http://cpansearch.perl.org/src/SULLR/IO-Socket-SSL-1.26/Changes");

  script_tag(name:"summary", value:"The IO::Socket::SSL module for Perl is prone to a security-
  bypass vulnerability because the application fails to properly validate certificate hostnames.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to bypass
  certain security restrictions, which may aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to 1.26 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.26" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.26", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );