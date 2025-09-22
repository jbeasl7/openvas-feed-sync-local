# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170089");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-03-28 08:06:32 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2013-4489", "CVE-2013-4490", "CVE-2013-4546");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab Community Edition 4.2.x - 5.4.0, 6.x - 6.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2013-4489: remote code execution vulnerability in the code search feature of GitLab

  - CVE-2013-4490: remote code execution vulnerability in the SSH key upload feature of GitLab

  - CVE-2013-4546: remote code execution vulnerability in the repository import feature of older
  versions of GitLab");

  script_tag(name:"affected", value:"GitLab version 4.2.x through 5.4.0 and 6.x through 6.2.2");

  script_tag(name:"solution", value:"Update to version 5.4.1, 6.2.3 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2013/11/04/gitlab-ce-6-2-and-5-4-security-release/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
