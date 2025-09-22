# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128056");
  script_version("2024-10-11T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-07 13:40:01 +0000 (Mon, 07 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:N/A:C");

  script_cve_id("CVE-2024-31227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0.0 < 7.2.6, 7.4.0 DoS vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Potential Denial-of-service due to malformed ACL selectors");

  script_tag(name:"affected", value:"Redis version 7.0.0 through 7.2.5 and 7.4.x prior to 7.4.1.");

  script_tag(name:"solution", value:"Update to version 7.2.6, 7.4.1 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-38p4-26x2-vqhh");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

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