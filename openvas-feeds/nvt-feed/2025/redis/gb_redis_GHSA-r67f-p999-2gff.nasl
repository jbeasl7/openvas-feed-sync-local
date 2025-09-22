# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154369");
  script_version("2025-04-25T05:39:37+0000");
  script_tag(name:"last_modification", value:"2025-04-25 05:39:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-24 03:47:36 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-21605");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis DoS Vulnerability (GHSA-r67f-p999-2gff)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated client can cause unlimited growth of output
  buffers, until the server runs out of memory or is killed.");

  script_tag(name:"affected", value:"Redis version 2.6 through 7.4.2.");

  script_tag(name:"solution", value:"Update to version 6.2.18, 7.2.8, 7.4.3 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-r67f-p999-2gff");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.18");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.8");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.4.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "2.6", test_version_up: "6.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.18");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.8");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.4", test_version_up: "7.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
