# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142627");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-07-19 06:02:19 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 12:14:00 +0000 (Thu, 28 Oct 2021)");

  script_cve_id("CVE-2019-10192", "CVE-2019-10193");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Multiple Vulnerabilities (Mar 2019)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"impact", value:"Redis is prone to multiple buffer overflow vulnerabilities:

  - Heap-buffer overflow vulnerability was found in the Redis hyperloglog data structure (CVE-2019-10192)

  - Stack-buffer overflow vulnerability was found in the Redis hyperloglog data structure (CVE-2019-10193)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Redis versions 3.x before 3.2.13, 4.x before 4.0.14 and 5.x before 5.0.4.");

  script_tag(name:"solution", value:"Update to version 3.2.13, 4.0.14, 5.0.4 or later.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/antirez/redis/3.2/00-RELEASENOTES");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/antirez/redis/4.0/00-RELEASENOTES");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/antirez/redis/5.0/00-RELEASENOTES");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.0", test_version2: "3.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
