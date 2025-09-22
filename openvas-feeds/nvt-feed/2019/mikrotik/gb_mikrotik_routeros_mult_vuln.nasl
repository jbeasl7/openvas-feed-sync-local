# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142599");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-07-15 08:15:04 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:28:00 +0000 (Tue, 17 Jan 2023)");

  script_cve_id("CVE-2018-1157", "CVE-2018-1158", "CVE-2019-11477", "CVE-2019-11478",
                "CVE-2019-11479", "CVE-2019-13954", "CVE-2019-13955");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.44.5 (LTS), < 6.45.1 (Stable) Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.44.5 (LTS) and
  6.45.1 (Stable).");

  script_tag(name:"solution", value:"Update to version 6.44.5 (LTS), 6.45.1 (Stable) or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/stable-release-tree");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/long-term-release-tree");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.44.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^6\.45") {
  if (version_is_less(version: version, test_version: "6.45.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.45.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
