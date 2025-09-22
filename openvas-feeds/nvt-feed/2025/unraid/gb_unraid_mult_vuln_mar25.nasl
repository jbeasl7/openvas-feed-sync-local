# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154290");
  script_version("2025-04-04T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-04-04 15:42:05 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-04 04:33:15 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-15 15:15:10 +0000 (Wed, 15 Jan 2025)");

  script_cve_id("CVE-2025-29266", "CVE-2024-12705", "CVE-2024-11187", "CVE-2025-0725",
                "CVE-2025-0665", "CVE-2025-0167", "CVE-2024-50349", "CVE-2024-52006",
                "CVE-2024-12243", "CVE-2024-12133", "CVE-2025-24928", "CVE-2024-56171",
                "CVE-2025-21490", "CVE-2025-26465", "CVE-2025-26466", "CVE-2024-12084",
                "CVE-2024-12085", "CVE-2024-12086", "CVE-2024-12087", "CVE-2024-12088");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS < 7.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_unraid_consolidation.nasl");
  script_mandatory_keys("unraid/detected");

  script_tag(name:"summary", value:"Unraid OS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-29266: Reliance on IP address for authentication

  - Multiple issues in various third-party components");

  script_tag(name:"solution", value:"Update to version 7.0.1 or later.");

  script_xref(name:"URL", value:"https://docs.unraid.net/unraid-os/release-notes/7.0.1/");
  script_xref(name:"URL", value:"https://edac.dev/security/CVE-2025-29266/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
