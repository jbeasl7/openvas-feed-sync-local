# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147244");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-12-02 04:26:41 +0000 (Thu, 02 Dec 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-03 16:25:07 +0000 (Fri, 03 Dec 2021)");

  script_cve_id("CVE-2021-43792", "CVE-2021-43793", "CVE-2021-43794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.7.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-43792: Users without tag group permissions can view and receive notifications for
  previously watched tags

  - CVE-2021-43793: Bypass of Poll voting limits

  - CVE-2021-43794: Anonymous user cache poisoning via development-mode header");

  script_tag(name:"affected", value:"Discourse prior to version 2.7.11.");

  script_tag(name:"solution", value:"Update to version 2.7.11 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-pq2x-vq37-8522");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jq7h-44vc-h6qx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-249g-pc77-65hp");

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

if (version_is_less(version: version, test_version: "2.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
