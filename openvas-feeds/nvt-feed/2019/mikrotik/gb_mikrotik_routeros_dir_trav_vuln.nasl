# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142239");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-04-10 14:07:57 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 19:19:00 +0000 (Tue, 17 Dec 2019)");

  script_cve_id("CVE-2019-3943");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS Directory Traversal Vulnerability (CVE-2019-3943)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to an authenticated directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The directory traversal allows an authenticated attacker to
  access files outside of the sandbox path with mkdir, read and write access.");

  script_tag(name:"impact", value:"An authenticated attacker may have read access to the entire
  filesystem and write access to all locations that aren't marked as read-only.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.42.12 and prior
  (Long-term release) and 6.43.12 and prior (Stable release).");

  script_tag(name:"solution", value:"Update to version 6.43.13 (Long-term release),
  6.44 (Stable release) or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/bugfix-release-tree");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/release-candidate-release-tree");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2019-16");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.42.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.43.13");
  security_message(port: 0, data: report);
  exit(0);
}
else if (version_in_range(version: version, test_version: "6.43", test_version2: "6.43.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
