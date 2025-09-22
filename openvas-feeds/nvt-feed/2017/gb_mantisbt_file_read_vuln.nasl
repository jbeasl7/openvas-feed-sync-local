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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140285");
  script_version("2022-03-15T08:15:23+0000");
  script_tag(name:"last_modification", value:"2022-03-15 08:15:23 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2017-08-08 15:08:03 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-09 19:33:00 +0000 (Wed, 09 Aug 2017)");

  script_cve_id("CVE-2017-12419");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("MantisBT 1.x, 2.x Arbitrary File Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");

  script_tag(name:"summary", value:"MantisBT is prone to an arbitrary file read vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"If, after successful installation of MantisBT on MySQL/MariaDB, the
administrator does not remove the 'admin' directory (as recommended in the 'Post-installation and upgrade tasks'
section of the MantisBT Admin Guide), and the MySQL client has a local_infile setting enabled (in php.ini
mysqli.allow_local_infile, or the MySQL client config file, depending on the PHP setup), an attacker may take
advantage of MySQL's 'connect file read' feature to remotely access files on the MantisBT server.");

  script_tag(name:"affected", value:"MantisBT version 1.x and 2.x.");

  script_tag(name:"solution", value:"Delete the 'admin' directory, disabling mysqli.allow_local_infile in php.ini.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=23173");
  script_xref(name:"URL", value:"https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.install.postcommon");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/admin/install.php?install=3";

if (http_vuln_check(port: port, url: url, pattern: "Installing Database", check_header: TRUE)) {
  report = "The installer script is accessible at " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
