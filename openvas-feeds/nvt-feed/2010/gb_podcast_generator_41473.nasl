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

CPE = "cpe:/a:podcast_generator:podcast_generator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100709");
  script_version("2022-09-26T10:10:50+0000");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"creation_date", value:"2010-07-09 12:33:08 +0200 (Fri, 09 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Podcast Generator <= 1.3 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_podcast_generator_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("podcast_generator/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Podcast Generator is prone to a directory traversal
  vulnerability because it fails to sufficiently validate user-supplied input data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting the issue can allow an attacker to obtain sensitive
  information that may aid in further attacks.");

  script_tag(name:"affected", value:"Podcast Generator version 1.3 and prior on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41473");
  script_xref(name:"URL", value:"http://www.scribd.com/doc/28080332/Podcast-Generator-1-3-Arbitrary-File-Download-Windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
