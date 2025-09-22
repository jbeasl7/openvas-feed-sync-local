# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170225");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2022-11-14 09:47:24 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-26 16:12:00 +0000 (Wed, 26 Oct 2022)");

  script_cve_id("CVE-2022-27622", "CVE-2022-27623");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) 6.2.x, 7.x < 7.1-42661 Multiple Vulnerabilities (Synology-SA-22:18)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2022-27622: Server-Side Request Forgery (SSRF) vulnerability in Package Center functionality
  in Synology DiskStation Manager (DSM) before 7.1-42661 allows remote authenticated users to access
  intranet resources via unspecified vectors.

  - CVE-2022-27623: Missing authentication for critical function vulnerability in iSCSI management
  functionality in Synology DiskStation Manager allows remote attackers to read or write arbitrary
  files via unspecified vectors.");

  script_tag(name:"affected", value:"Synology DSM version 6.2.x, 7.x prior to
  7.1-42661.");

  script_tag(name:"solution", value:"Update to firmware version 7.1-42661 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_18");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "6.2") >= 0) && (revcomp(a: version, b: "7.1-42661") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1-42661");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
