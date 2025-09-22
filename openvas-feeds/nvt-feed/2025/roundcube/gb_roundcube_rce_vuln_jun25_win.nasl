# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154613");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-02 07:14:07 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-49113");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail RCE Vulnerability (Jun 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("roundcube/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to an authenticated remote code
  execution (RCE) vulnerability via php object deserialization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roundcube Webmail prior to version 1.5.10 and 1.16.x prior to
  1.6.11.

  Note: According to the security research team the flaw has been introduced in version 1.1.0 but no
  official information / source is available.");

  script_tag(name:"solution", value:"Update to version 1.5.10, 1.6.11 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/02/1");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/pull/9865");
  script_xref(name:"URL", value:"https://fearsoff.org/research/roundcube");
  script_xref(name:"URL", value:"https://github.com/rasool13x/exploit-CVE-2025-49113");

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

if (version_is_less(version: version, test_version: "1.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.6", test_version_up: "1.6.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
