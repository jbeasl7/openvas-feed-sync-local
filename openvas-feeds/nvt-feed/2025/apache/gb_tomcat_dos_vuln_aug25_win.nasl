# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171673");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-18 14:17:03 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-8671", "CVE-2025-48989");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat HTTP/2 Protocol DoS Vulnerability (MadeYouReset) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to is prone to a denial of service (DoS)
  vulnerability in the HTTP/2 protocol dubbed 'MadeYouReset'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A mismatch caused by client-triggered server-sent stream resets
  between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may
  result in excessive server resource consumption leading to denial-of-service (DoS). By opening
  streams and then rapidly triggering the server to reset them, using malformed frames or flow
  control errors, an attacker can exploit incorrect stream accounting. Streams reset by the server
  are considered closed at the protocol level, even though backend processing continues. This
  allows a client to cause the server to handle an unbounded number of concurrent streams on a
  single connection.");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.107 and prior, 10.x through 10.1.43
  and 11.0.0-M1 through 11.0.9.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that the whole 10.x branch and all versions prior to 9.x are affected by these flaws.
  If you disagree with this assessment and want to accept the risk please create an override for
  this result.");

  script_tag(name:"solution", value:"Update to version 9.0.108, 10.1.44, 11.0.10 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/9ydfg0xr0tchmglcprhxgwhj0hfwxlyf");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/p09775q0rd185m6zz98krg0fp45j8kr0");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.108");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.44");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.10");
  script_xref(name:"URL", value:"https://galbarnahum.com/posts/made-you-reset-intro");
  script_xref(name:"URL", value:"https://deepness-lab.org/publications/madeyoureset/");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/767506");
  script_xref(name:"URL", value:"https://thehackernews.com/2025/08/new-http2-madeyoureset-vulnerability.html");

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

if (version_is_less_equal(version: version, test_version: "9.0.107")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.108", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.44", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
