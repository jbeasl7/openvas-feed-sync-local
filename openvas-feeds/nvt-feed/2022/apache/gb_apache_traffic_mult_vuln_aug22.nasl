# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126109");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-08-11 13:24:25 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-13 03:15:00 +0000 (Sat, 13 Aug 2022)");

  script_cve_id("CVE-2022-25763", "CVE-2022-28129", "CVE-2022-31779", "CVE-2022-31780",
                "CVE-2021-37150");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 8.0.0 <= 8.1.4, 9.0.0 <= 9.1.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_tag(name:"summary", value:"Apache Traffic Server (ATS) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-37150: Protocol vs scheme mismatch.

  - CVE-2022-25763: Improper input validation on HTTP/2 headers.

  - CVE-2022-28129: Insufficient validation of HTTP/1.x headers.

  - CVE-2022-31779: Improper HTTP/2 scheme and method validation.

  - CVE-2022-31780: HTTP/2 framing vulnerabilities.");

  script_tag(name:"affected", value:"Apache Traffic Server version 8.0.0 through 8.1.4 and 9.0.0
  through 9.1.2.");

  script_tag(name:"solution", value:"Update to version 8.1.5, 9.1.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/qxyw6r3d5xllvzggqhqfcz2q11l9gtzx");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/yhxmll6nog4ktn28676krlqpvvwpkh1v");

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

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
