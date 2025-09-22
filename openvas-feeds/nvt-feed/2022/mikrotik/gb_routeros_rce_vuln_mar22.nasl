# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124040");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-03-18 15:35:22 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-28 13:17:00 +0000 (Mon, 28 Mar 2022)");

  script_cve_id("CVE-2021-41987");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS RCE Vulnerability (CVE-2021-41987)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the SCEP Server of RouterOS in certain Mikrotik products, an
  attacker can trigger a heap-based buffer overflow that leads to remote code execution.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions prior to 6.48.6, 6.49.x prior to
  6.49.1 and 7.x prior to 7.1.");

  # nb: The only reference to a fix for SCEP on https://mikrotik.com/download/changelogs matching
  # the release date 2021/11/17 in the linked advisory is the following:
  # *) certificate - improved stability when sending bogus SCEP message;
  # Every release containing this changelog entry has been assumed to contain a fix.
  script_tag(name:"solution", value:"Update to version 6.48.6, 6.49.1, 7.1 or later.");

  script_xref(name:"URL", value:"https://teamt5.org/en/posts/vulnerability-mikrotik-cve-2021-41987/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.48.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.48.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.49.0", test_version_up: "6.49.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.1");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
