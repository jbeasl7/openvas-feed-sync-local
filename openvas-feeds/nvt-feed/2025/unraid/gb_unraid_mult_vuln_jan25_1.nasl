# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153886");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-29 01:35:45 +0000 (Wed, 29 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-24 01:15:04 +0000 (Sun, 24 Nov 2024)");

  script_cve_id("CVE-2024-11691", "CVE-2023-48795", "CVE-2024-9143", "CVE-2024-8932",
                "CVE-2024-8929", "CVE-2024-11236", "CVE-2024-11234", "CVE-2024-11233",
                "CVE-2018-14628", "CVE-2024-10524");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS < 6.12.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_unraid_consolidation.nasl");
  script_mandatory_keys("unraid/detected");

  script_tag(name:"summary", value:"Unraid OS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - No CVE: Reflected cross-site scripting (XSS) via URL parameters in the Unraid web interface

  - No CVE: Stored cross-site scripting (XSS) in various web interface fields

  - CVE-2024-11691, CVE-2023-48795, CVE-2024-9143, CVE-2024-8932, CVE-2024-8929, CVE-2024-11236,
    CVE-2024-11234, CVE-2024-11233, CVE-2018-14628, CVE-2024-10524: Multiple third party component
    issues (firefox, libssh2, openssl, php, samba, wget)");

  script_tag(name:"affected", value:"Unraid OS version 6.12.13 and prior.");

  script_tag(name:"solution", value:"Update to version 6.12.14 or later.");

  script_xref(name:"URL", value:"https://unraid.net/blog/cvd");
  script_xref(name:"URL", value:"https://unraid.net/blog/6-12-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.12.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.12.14");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
