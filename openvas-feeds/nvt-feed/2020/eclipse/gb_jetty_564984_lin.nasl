# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144238");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-07-15 06:13:23 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2019-17638");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Vulnerability (CVE-2019-17638) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability where sensitive information about
  clients could be obtained.");

  script_tag(name:"insight", value:"In case of too large response headers, Jetty throws an exception to produce
  an HTTP 431 error. When this happens, the ByteBuffer containing the HTTP response headers is released back to
  the ByteBufferPool twice. Because of this double release, two threads can acquire the same ByteBuffer from the
  pool and while thread1 is about to use the ByteBuffer to write response1 data, thread2 fills the ByteBuffer
  with response2 data. Thread1 then proceeds to write the buffer that now contains response2 data. This results
  in client1, which issued request1 and expects responses, to see response2 which could contain sensitive data
  belonging to client2 (HTTP session ids, authentication credentials, etc.).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.27.v20200227 prior to 9.4.30.v20200611.");

  script_tag(name:"solution", value:"Update to version 9.4.30.v20200611 or later.");

  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=564984");
  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/issues/4936");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                          exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_greater_equal(version: version, test_version: "9.4.27.20200227") &&
    version_is_less(version: version, test_version: "9.4.30.20200611")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.30.20200611", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
