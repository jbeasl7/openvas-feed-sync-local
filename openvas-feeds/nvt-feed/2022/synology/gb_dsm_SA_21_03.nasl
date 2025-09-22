# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170238");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2022-11-16 10:31:34 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 20:40:00 +0000 (Wed, 03 Aug 2022)");

  script_cve_id("CVE-2021-26563", "CVE-2021-29088", "CVE-2021-33182", "CVE-2022-22684");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) 6.2.x < 6.2.4-25553 Multiple Vulnerabilities (Synology-SA-21:03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2021-26563: Incorrect authorization vulnerability in synoagentregisterd

  - CVE-2021-29088: Path traversal in cgi component

  - CVE-2021-33182: Path traversal in PDF Viewer component

  - CVE-2022-22684: OS Command Injection in task management component");

  script_tag(name:"affected", value:"Synology DSM version 6.2.x prior to
  6.2.4-25553.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.4-25553 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_21_03");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^6\.2" && (revcomp(a: version, b: "6.2.4-25553") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4-25553");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
