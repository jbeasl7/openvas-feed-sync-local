# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103339");
  script_version("2022-05-25T13:03:27+0000");
  script_tag(name:"last_modification", value:"2022-05-25 13:03:27 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-11-16 11:22:53 +0100 (Wed, 16 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-3829", "CVE-2011-3830", "CVE-2011-3831", "CVE-2011-3832",
                "CVE-2011-3833");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Support Incident Tracker (SiT!) <= 3.65 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/detected");

  script_tag(name:"summary", value:"Support Incident Tracker (SiT!) is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following input validation vulnerabilities exist:

  1. A cross-site scripting vulnerability

  2. An SQL injection vulnerability

  3. A PHP code injection vulnerability

  4. A path disclosure vulnerability

  5. An arbitrary file upload vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute
  arbitrary code, steal cookie-based authentication credentials, compromise the application, access
  or modify data, or exploit latent vulnerabilities in the underlying database. Access to sensitive
  data may also be used to launch further attacks against a vulnerable computer.");

  script_tag(name:"affected", value:"Support Incident Tracker (SiT!) version 3.65 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50632");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-78/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-76/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-79/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-75/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-77/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
