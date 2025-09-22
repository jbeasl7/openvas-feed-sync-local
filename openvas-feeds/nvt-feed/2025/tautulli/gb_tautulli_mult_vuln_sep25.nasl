# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tautulli:tautulli";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155327");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-15 07:56:58 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-18 17:23:40 +0000 (Thu, 18 Sep 2025)");

  script_cve_id("CVE-2025-58760", "CVE-2025-58761", "CVE-2025-58762", "CVE-2025-58763");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tautulli < 2.16.0 Multiple Vulnerabilities - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tautulli_http_detect.nasl");
  script_mandatory_keys("tautulli/detected");

  script_tag(name:"summary", value:"Tautulli is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-58760: Unauthenticated path traversal in '/image' endpoint

  - CVE-2025-58761: Unauthenticated path traversal in 'real_pms_image_proxy'

  - CVE-2025-58762: Authenticated remote code execution (RCE) via write primitive and 'Script'
  notification agent

  - CVE-2025-58763: Authenticated remote code execution (RCE) via command injection");

  script_tag(name:"affected", value:"Tautulli version 2.15.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.16.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-8g4r-8f3f-hghp");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-r732-m675-wj7w");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-pxhr-29gv-4j8v");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-jrm9-r57q-6cvf");

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

if (version_is_less(version: version, test_version: "2.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
