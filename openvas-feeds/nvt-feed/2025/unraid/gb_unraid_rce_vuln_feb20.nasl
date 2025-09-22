# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114945");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-31 09:59:54 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 17:15:00 +0000 (Fri, 17 Apr 2020)");

  script_cve_id("CVE-2020-5847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS < 6.8.1 Web UI RCE Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_unraid_consolidation.nasl");
  script_mandatory_keys("unraid/detected");

  script_tag(name:"summary", value:"Unraid OS is prone to a remote code execution (RCE)
  vulnerability in the Web UI.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Unraid OS version 6.8.0 and prior.");

  script_tag(name:"solution", value:"Update to version 6.8.1 or later.");

  script_xref(name:"URL", value:"https://sysdream.com/cve-2020-5847-cve-2020-5849-unraid/");
  script_xref(name:"URL", value:"https://forums.unraid.net/topic/87218-unraid-os-version-681-available/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
