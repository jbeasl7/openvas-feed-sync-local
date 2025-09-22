# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145822");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-04-26 06:14:55 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 16:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-31760", "CVE-2021-31761", "CVE-2021-31762");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Webmin <= 1.973 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-31760: Cross Site Request Forgery (CSRF) which might lead to a Remote Command Execution (RCE)
    through Webmin's running process feature

  - CVE-2021-31761: Reflected Cross Site Scripting (XSS) which might lead to an RCE through Webmin's running
    process feature

  - CVE-2021-31762: CSRF to create a privileged user through Webmin's add users feature, and then get a
    reverse shell through Webmin's running process feature.

  Note: The vendor added the following additional information regarding these vulnerabilities:

  If Webmin is installed using the non-recommended setup.pl script, checking for unknown referrers is not
  enabled by default. This opens the system up to XSS and CSRF attacks using malicious links. Fortunately
  the standard RPM, Deb, TAR and Solaris packages do not use this script and so are not vulnerable. If you
  did install using the setup.pl script, the vulnerability can be fixed by adding the line 'referers_none=1'
  to '/etc/webmin/config'.");

  script_tag(name:"affected", value:"Webmin version 1.973 and probably prior.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.webmin.com/security.html");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-31760");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-31761");
  script_xref(name:"URL", value:"https://github.com/Mesh3l911/CVE-2021-31762");

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

if (version_is_less_equal(version: version, test_version: "1.973")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
