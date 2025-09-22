# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147106");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-11-05 05:11:13 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 17:08:00 +0000 (Fri, 05 Nov 2021)");

  script_cve_id("CVE-2021-37147", "CVE-2021-37148", "CVE-2021-37149", "CVE-2021-41585",
                "CVE-2021-43082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 8.0.0 < 8.1.3, 9.0.0 < 9.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-37147 Request Smuggling - LF line ending

  - CVE-2021-37148 Request Smuggling - transfer encoding validation

  - CVE-2021-37149 Request Smuggling - multiple attacks

  - CVE-2021-41585 ATS stops accepting connections on FreeBSD

  - CVE-2021-43082 heap-buffer-overflow with stats-over-http plugin");

  script_tag(name:"affected", value:"Apache Traffic Server version 8.0.0 through 8.1.2 and 9.0.0
  through 9.1.0.");

  script_tag(name:"solution", value:"Update to version 8.1.3, 9.1.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/k01797hyncx53659wr3o72s5cvkc3164");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
