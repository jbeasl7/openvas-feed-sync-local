# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153718");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-01-07 03:00:05 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 14:20:13 +0000 (Fri, 05 Sep 2025)");

  script_cve_id("CVE-2024-46981");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis RCE Vulnerability (GHSA-39h2-x6c4-6w4c)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user may use a specially crafted Lua script to
  manipulate the garbage collector and potentially lead to remote code execution.");

  script_tag(name:"affected", value:"Redis prior to version 6.2.17, 7.x prior to 7.2.7 and 7.4.x
  prior to 7.4.2.");

  script_tag(name:"solution", value:"Update to version 6.2.17, 7.2.7, 7.4.2 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-39h2-x6c4-6w4c");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.17");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.7");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.4.2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.4", test_version_up: "7.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
