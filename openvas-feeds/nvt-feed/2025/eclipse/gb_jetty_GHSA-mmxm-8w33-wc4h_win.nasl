# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124891");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-21 07:51:24 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-5115", "CVE-2025-8671");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (MadeYouReset) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability in the HTTP/2 protocol dubbed 'MadeYouReset'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability takes advantage of a design flaw in the
  HTTP/2 protocol - While HTTP/2 has a limit on the number of concurrently active streams per
  connection (which is usually 100, and is set by the parameter SETTINGS_MAX_CONCURRENT_STREAMS),
  the number of active streams is not counted correctly - when a stream is reset, it is immediately
  considered not active, and thus unaccounted for in the active streams counter. While the protocol
  does not count those streams as active, the server's backend logic still processes and handles
  the requests that were canceled. Thus, the attacker can exploit this vulnerability to cause the
  server to handle an unbounded number of concurrent streams from a client on the same connection.
  The exploitation is very simple: the client issues a request in a stream, and then sends the
  control frame that causes the server to send a RST_STREAM.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.3.0 through 9.4.57 10.0.0 through
  10.0.25, 11.0.0 through 11.0.25, 12.0.0 through 12.0.24 and 12.1.0.alpha0 through 12.1.0.beta2.");

  script_tag(name:"solution", value:"Update to version 9.4.58, 10.0.26, 11.0.26, 12.0.25,
  12.1.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-mmxm-8w33-wc4h");
  script_xref(name:"URL", value:"https://galbarnahum.com/posts/made-you-reset-intro");
  script_xref(name:"URL", value:"https://deepness-lab.org/publications/madeyoureset/");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/767506");
  script_xref(name:"URL", value:"https://thehackernews.com/2025/08/new-http2-madeyoureset-vulnerability.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.4.58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.58", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0.0", test_version_up: "12.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.1.0.alpha0", test_version_up: "12.1.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.1.0.beta3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
