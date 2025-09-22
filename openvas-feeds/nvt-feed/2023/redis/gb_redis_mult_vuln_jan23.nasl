# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149156");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-01-18 03:52:35 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-02 14:23:00 +0000 (Thu, 02 Feb 2023)");

  script_cve_id("CVE-2022-35977", "CVE-2023-22458");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 6.2.x < 6.2.9, 7.0.x < 7.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-35977: Integer overflow in the Redis SETRANGE and SORT/SORT_RO commands can drive
  Redis to OOM panic

  - CVE-2023-22458: Integer overflow in the Redis HRANDFIELD and ZRANDMEMBER commands can lead to
  denial of service");

  script_tag(name:"affected", value:"Redis versions 6.2.x prior to 6.2.9 and 7.0.x prior to
  7.0.8.");

  script_tag(name:"solution", value:"Update to version 6.2.9, 7.0.8 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-r8w2-2m53-gprj");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-mrcw-fhw9-fj8j");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.8");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.2.9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.9/7.0.8");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
