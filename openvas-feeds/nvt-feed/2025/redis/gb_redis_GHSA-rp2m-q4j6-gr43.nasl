# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127923");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-07-08 07:39:51 +0000 (Tue, 08 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 15:16:30 +0000 (Fri, 05 Sep 2025)");

  script_cve_id("CVE-2025-32023");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis Buffer Overflow Vulnerability (GHSA-rp2m-q4j6-gr43)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user may use a specially crafted string to
  trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to
  remote code execution.");

  script_tag(name:"affected", value:"Redis versions 2.8.x prior to 6.2.19, 7.2.x prior to 7.2.10,
  7.4.x prior to 7.4.5 and 8.0.x prior to 8.0.3.");

  script_tag(name:"solution", value:"Update to version 6.2.19, 7.2.10, 7.4.5, 8.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-rp2m-q4j6-gr43");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.19");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.10");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.4.5");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/8.0.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "2.8.0", test_version_up: "6.2.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.19");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.4.0", test_version_up: "7.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
