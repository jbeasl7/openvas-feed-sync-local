# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elog_project:elog";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118901");
  script_version("2026-11-06T05:39:10+0000");
  script_tag(name:"last_modification", value:"2026-11-06 05:39:10 +0000 (Fri, 06 Nov 2026)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2025-11-05 04:17:00 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-62618");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ELOG < 3.1.6 File Upload Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elog_http_detect.nasl");
  script_mandatory_keys("elog/detected");

  script_tag(name:"summary", value:"ELOG is prone to a file upload stored cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ELOG allows an authenticated user to upload arbitrary HTML
  files. The HTML content is executed in the context of other users when they open the file.
  Because ELOG includes usernames and password hashes in certain HTTP requests, an attacker can
  obtain the target's credentials and replay them or crack the password hash offline.");

  script_tag(name:"affected", value:"ELOG prior to version 3.1.6.");

  script_tag(name:"solution", value:"- Update to the upcoming version 3.1.6 or later

  - For RPM package based installations install the specific elog-3.1.5-20251014 .rpm package which
  seems to also include a fix

  Note: Please create an override for this result if the .rpm package has been installed and the
  version is still at 3.1.5.");

  script_xref(name:"URL", value:"https://vulnerability.circl.lu/vuln/va-25-304-01");
  script_xref(name:"URL", value:"https://gitea.psi.ch/ELOG/elog/src/commit/8de22dcc33387b35bb1292c9a0f2ea0e5b0e6d42/doc/ChangeLog");
  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/7092ff64f6eb9521f8cc8c52272a020bf3730946");
  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/f81e5695c40997322fe2713bfdeba459d9de09dc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
