# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148414");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2022-07-08 02:57:13 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:36:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-2191");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-8mpp-f3f7-xc28) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SslConnection does not release ByteBuffers in case of error
  code paths. For example, TLS handshakes that require client-auth with clients that send expired
  certificates will trigger a TLS handshake errors and the ByteBuffers used to process the TLS
  handshake will be leaked.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 10.0.x through 10.0.9 and 11.0.x through
  11.0.9.");

  script_tag(name:"solution", value:"Update to version 10.0.10, 11.0.10 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-8mpp-f3f7-xc28");
  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/issues/8161");

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

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
