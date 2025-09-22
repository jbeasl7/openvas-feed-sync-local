# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103877");
  script_version("2022-05-25T21:46:57+0000");
  script_tag(name:"last_modification", value:"2022-05-25 21:46:57 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2014-01-09 18:58:01 +0100 (Thu, 09 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2013-7174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 'f' Parameter Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"QNAP QTS 4.0.3 and possibly earlier versions contain a path
  traversal vulnerability via the cgi-bin/jc.cgi CGI script. The script accepts an 'f' parameter which
  takes an unrestricted file path as input.");

  script_tag(name:"impact", value:"A remote attacker could exploit the vulnerability using
  directory-traversal characters ('../') to access arbitrary files that contain sensitive
  information. Information harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"QNAP QTS version prior to 4.1.0.");

  script_tag(name:"solution", value:"Update to version 4.1.0");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64719");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_is_less(version:version, test_version:"4.1.0")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"4.1.0");
    security_message(port:0, data:report);
    exit(0);
}

exit(99);
