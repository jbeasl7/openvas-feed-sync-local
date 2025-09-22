# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143789");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2020-04-30 05:37:04 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2020-9481");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) HTTP/2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a denial of service vulnerability due to
  HTTP/2 slow read attack.");

  script_tag(name:"affected", value:"Apache Traffic Server versions 6.0.0 - 6.2.3, 7.0.0 - 7.1.9 and 8.0.0 - 8.0.6.");

  script_tag(name:"solution", value:"Update to version 7.1.10, 8.0.7 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r21ddaf0a4a973f3c43c7ff399ae50d2f858f13f87bd6a9551c5cf6db%40%3Cannounce.trafficserver.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.2.3") ||
    version_in_range(version: version, test_version: "7.0.0", test_version2: "7.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
