# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155259");
  script_version("2025-09-02T09:15:41+0000");
  script_tag(name:"last_modification", value:"2025-09-02 09:15:41 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-02 02:34:28 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-8671");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lighttpd < 1.4.80 DoS Vulnerability (MadeYouReset)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_mandatory_keys("lighttpd/detected");

  script_tag(name:"summary", value:"Lighttpd is prone to a denial of service (DoS) vulnerability in
  the HTTP/2 protocol dubbed 'MadeYouReset'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A mismatch caused by client-triggered server-sent stream resets
  between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may
  result in excessive server resource consumption leading to denial-of-service (DoS). By opening
  streams and then rapidly triggering the server to reset them, using malformed frames or flow
  control errors, an attacker can exploit incorrect stream accounting. Streams reset by the server
  are considered closed at the protocol level, even though backend processing continues. This
  allows a client to cause the server to handle an unbounded number of concurrent streams on a
  single connection.");

  script_tag(name:"affected", value:"Lighttpd version 1.4.79 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.80 or later.");

  script_xref(name:"URL", value:"https://www.lighttpd.net/2025/8/13/1.4.80/");
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

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.4.80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.80");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
