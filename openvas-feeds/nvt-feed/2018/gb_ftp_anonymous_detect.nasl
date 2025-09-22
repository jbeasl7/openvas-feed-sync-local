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
  script_oid("1.3.6.1.4.1.25623.1.0.900600");
  script_version("2021-10-20T09:03:29+0000");
  script_tag(name:"last_modification", value:"2021-10-20 09:03:29 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-10-23 08:55:22 +0200 (Tue, 23 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-1999-0497");
  script_name("Anonymous FTP Login Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_mandatory_keys("ftp/anonymous_ftp/detected");

  script_tag(name:"solution", value:"If you do not want to share files, you should disable anonymous
  logins.");

  script_tag(name:"insight", value:"A host that provides an FTP service may additionally provide
  Anonymous FTP access as well. Under this arrangement, users do not strictly need an account on the
  host. Instead the user typically enters 'anonymous' or 'ftp' when prompted for username. Although
  users are commonly asked to send their email address as their password, little to no verification
  is actually performed on the supplied data.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"impact", value:"Based on the files accessible via this anonymous FTP login and
  the permissions of this account an attacker might be able to:

  - gain access to sensitive files

  - upload or delete files.");

  script_tag(name:"summary", value:"Reports if the remote FTP Server allows anonymous logins.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

if( ! get_kb_item( "ftp/" + port + "/anonymous" ) )
  exit( 99 );

if( ! report = get_kb_item( "ftp/" + port + "/anonymous_report" ) )
  exit( 99 );

security_message( port:port, data:report );
exit( 0 );