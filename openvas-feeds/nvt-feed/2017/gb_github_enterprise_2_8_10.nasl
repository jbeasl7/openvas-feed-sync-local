# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:github:github_enterprise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140227");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-30 14:14:15 +0200 (Thu, 30 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("GitHub Enterprise < 2.8.10 Multiple Vulnerabilities");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_github_enterprise_ssh_login_detect.nasl");
  script_mandatory_keys("github/enterprise/ssh-login/detected");

  script_tag(name:"summary", value:"GitHub Enterprise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following security updates have been included:

  - HIGH: Improper sanitization of user markup content, while not allowing full XSS, could have been
  abused to leak sensitive data or perform actions as the user viewing the content

  - LOW: Detect and reject any Git content that shows evidence of being part of a SHA-1 collision
  attack");

  script_tag(name:"affected", value:"GitHub Enterprise versions prior to 2.8.10.");

  script_tag(name:"solution", value:"Update to version 2.8.10 or later.");

  script_xref(name:"URL", value:"https://enterprise.github.com/releases/2.8.10/notes");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: version_regex is used as the HTTP detection is only extracting the major.minor version like
# e.g. "3.12".
if (!version = get_app_version(cpe: CPE, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
