# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152770");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-26 02:43:43 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-41110");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker AuthZ Plugin Bypass Vulnerability (GHSA-v23v-6jw2-98fq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to an AuthZ plugin bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A security vulnerability has been detected in Docker Engine,
  which could allow an attacker to bypass authorization plugins (AuthZ) under specific
  circumstances.");

  script_tag(name:"affected", value:"Docker version 19.03.x through 19.03.15, 20.x through
  20.10.27, 23.x through 23.0.14, 24.x through 24.0.9, 25.x through 25.0.5, 26.x through 26.0.2,
  26.1.x through 26.1.4, 27.x through 27.0.3 and 27.1.0.");

  script_tag(name:"solution", value:"Update to version 23.0.15, 26.1.5, 27.1.1 or later.");

  script_xref(name:"URL", value:"https://www.docker.com/blog/docker-security-advisory-docker-engine-authz-plugin/");
  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "19.03.0", test_version2: "19.03.15") ||
    version_in_range(version: version, test_version: "20.0", test_version2: "20.10.27") ||
    version_in_range(version: version, test_version: "23.0", test_version2: "23.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.15");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "24.0", test_version2: "24.0.9") ||
    version_in_range(version: version, test_version: "25.0", test_version2: "25.0.5") ||
    version_in_range(version: version, test_version: "26.0", test_version2: "26.0.2") ||
    version_in_range(version: version, test_version: "26.1", test_version2: "26.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.1.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "27.1.0", test_version_up: "27.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
