# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154979");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 03:06:07 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2025-59948");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver 1.6.2 - 1.23.0 Cache Poisoning Vulnerability (Rebirthday Attack)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a cache poisoning
  vulnerability (Rebirthday Attack).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Resolvers supporting ECS need to segregate outgoing queries to
  accommodate for different outgoing ECS information. This re-opens up resolvers to a birthday
  paradox attack (Rebirthday Attack) that tries to match the DNS transaction ID in order to cache
  non-ECS poisonous replies.");

  script_tag(name:"affected", value:"Unbound DNS Resolver version 1.6.2 through 1.23.0.");

  script_tag(name:"solution", value:"Update to version 1.23.1 or later.");

  script_xref(name:"URL", value:"https://nlnetlabs.nl/downloads/unbound/CVE-2025-5994.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.6.2", test_version_up: "1.23.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.23.1");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
