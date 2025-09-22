# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128055");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-10-07 13:40:01 +0000 (Mon, 07 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-04 18:31:03 +0000 (Thu, 04 Sep 2025)");

  script_cve_id("CVE-2024-31449");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 2.6 < 6.2.16, 7.0.0. < 7.2.6, 7.4.0 RCE vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Lua library commands may lead to stack overflow and potential
  remote code execution vulnerability");

  script_tag(name:"affected", value:"Redis versions 2.6 through 6.2.15, 7.0.0 through 7.2.5 and
  7.4.0.");

  script_tag(name:"solution", value:"Update to version 6.2.16, 7.2.6, 7.4.1 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-whxg-wx83-85p5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "2.6", test_version_up: "6.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.4.0", test_version_up: "7.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);