# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148871");
  script_version("2023-11-09T05:05:33+0000");
  script_tag(name:"last_modification", value:"2023-11-09 05:05:33 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-11-08 10:20:46 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 16:22:00 +0000 (Tue, 29 Nov 2022)");

  script_cve_id("CVE-2022-3647");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Redis <= 7.0.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, which was classified as problematic, was
  found in Redis. Affected is the function sigsegvHandler of the file debug.c of the component
  Crash Report. The manipulation leads to denial of service.
  The real existence of this vulnerability is still doubted at the moment. The name of the
  patch is 0bf90d944313919eb8e63d3588bf63a367f020a3. It is recommended to apply a patch to fix
  this issue. VDB-211962 is the identifier assigned to this vulnerability.

  NOTE: The vendor claims that this is not a DoS because it applies to the crash logging
  mechanism which is triggered after a crash has occurred.");

  script_tag(name:"affected", value:"Redis version 7.0.5 and prior.");

  script_tag(name:"solution", value:"Apply the referenced patch.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/pull/11298");
  script_xref(name:"URL", value:"https://github.com/redis/redis/commit/0bf90d944313919eb8e63d3588bf63a367f020a3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
