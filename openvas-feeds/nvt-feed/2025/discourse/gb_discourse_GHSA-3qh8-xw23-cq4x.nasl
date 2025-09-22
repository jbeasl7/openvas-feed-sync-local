# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171433");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-04-14 06:33:13 +0000 (Mon, 14 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 17:18:20 +0000 (Tue, 26 Aug 2025)");

  script_cve_id("CVE-2024-24748", "CVE-2024-24827", "CVE-2024-27085", "CVE-2024-27100",
                "CVE-2024-28242");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-24748: Disclosure of the existence of secret subcategories

  - CVE-2024-24827: Denial of service (DoS) via Pixel Flood

  - CVE-2024-27085: DoS via invite - no max field size

  - CVE-2024-27100: DoS via Staff Actions Logs

  - CVE-2024-28242: Disclosure of the existence of secret categories with custom backgrounds");

  script_tag(name:"affected", value:"Discourse versions prior to 3.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.1, 3.3.0.beta1 or later.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/3-2-1-security-and-bug-fix-release/298237");
  script_xref(name:"URL", value:"https://meta.discourse.org/t/3-3-0-beta1-discourse-discover-opt-in-hot-topics-page-its-illegal-flag-reason-and-more/298236");

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

if (version_is_less(version: version, test_version: "3.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
