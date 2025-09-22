# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133015");
  script_version("2025-07-31T05:44:45+0000");
  script_tag(name:"last_modification", value:"2025-07-31 05:44:45 +0000 (Thu, 31 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-25 11:00:51 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");

  script_cve_id("CVE-2025-46686");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Redis DoS Vulnerability (GHSA-2r7g-8hpc-rpq9)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Allows memory consumption via a multi-bulk command composed
  of many bulks, sent by an authenticated user. This occurs because the server allocates memory
  for the command arguments of every bulk, even when the command is skipped because of
  insufficient permissions.");

  script_tag(name:"affected", value:"Redis versions through 8.0.3.");

  script_tag(name:"solution", value:"No known solution is available as of 25th July, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-2r7g-8hpc-rpq9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "8.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
