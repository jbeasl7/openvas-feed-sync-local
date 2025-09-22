# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:fxc:ae1021";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171699");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-22 12:28:50 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-11 17:29:32 +0000 (Mon, 11 Dec 2023)");

  script_cve_id("CVE-2023-49897");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FXC AE1021 / AE1021PE <= 2.0.9 OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_fxc_router_http_detect.nasl");
  script_mandatory_keys("sonos/detected");

  script_tag(name:"summary", value:"FXC AE1021 and AE1021PE routers are prone to an OS command
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If this vulnerability is exploited, an arbitrary OS command may
  be executed by an attacker who can log in to the product.");

  script_tag(name:"affected", value:"FXC AE1021 and AE1021PE routers firmware version 2.0.9 and
  prior.");

  script_tag(name:"solution", value:"Update to firmware version 2.0.10 or later and apply the
  mitigations from the referenced advisories.");

  script_xref(name:"URL", value:"https://www.fxc.jp/news/20231206");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-23-355-01");
  script_xref(name:"URL", value:"https://www.akamai.com/blog/security-research/zero-day-vulnerability-spreading-mirai-patched");
  script_xref(name:"URL", value:"https://jvn.jp/en/vu/JVNVU92152057/");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
