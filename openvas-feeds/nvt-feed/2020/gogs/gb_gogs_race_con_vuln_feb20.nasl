# Copyright (C) 2020 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112701");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-02-24 07:56:11 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-26 20:28:00 +0000 (Fri, 26 Jun 2020)");

  script_cve_id("CVE-2020-9329", "CVE-2020-14958");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gogs < 0.12 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-9329: Attackers may violate the admin-specified repo-creation policy due to an
  internal/db/repo.go race condition

  - CVE-2020-14958: MakeEmailPrimary in models/user_mail.go lacks a 'not the owner of the email'
  check

  - No CVE: Potential open redirection with i18n.

  - No CVE: Potential ability to delete files outside a repository.

  - No CVE: Potential XSS attack via .ipynb.

  - No CVE: Potential SSRF attack via webhooks.

  - No CVE: Potential CSRF attack in admin panel.

  - No CVE: Potential stored XSS attack in some browsers.

  - No CVE: Potential RCE on mirror repositories.

  - No CVE: Potential XSS attack with raw markdown API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Gogs versions prior to 0.12.0.");

  script_tag(name:"solution", value:"Update to version 0.12.0 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/releases/tag/v0.12.0");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5170");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5366");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5367");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5397");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5767");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/pull/5907");
  # nb: Seems to be still open, we're assuming that this has been fixed in the meantime
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5926");
  # nb: See Changelog entry, this fix has been included in 0.12.0
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/pull/5988");

  exit(0);
}

CPE = "cpe:/a:gogs:gogs";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version: version, test_version: "0.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.0", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
