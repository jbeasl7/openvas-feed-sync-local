# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170291");
  script_version("2024-03-15T15:36:48+0000");
  script_tag(name:"last_modification", value:"2024-03-15 15:36:48 +0000 (Fri, 15 Mar 2024)");
  # nb: This was initially a single VT but had to be split into two VTs in 2023. The original date
  # for both (the new and the old one) has been kept in this case.
  script_tag(name:"creation_date", value:"2022-11-16 10:31:34 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 18:19:00 +0000 (Mon, 03 Apr 2023)");

  script_cve_id("CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123",
                "CVE-2022-23124", "CVE-2022-23125");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) 6.2.x < 6.2.4-25556-6, 7.0.x < 7.0.1-42218-4, 7.1.x < 7.1-42661-1 Multiple Vulnerabilities (Synology-SA-22:06) - Unreliable Remote Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Multiple vulnerabilities allow remote attackers to obtain
  sensitive information and possibly execute arbitrary code via a susceptible version of
  Synology DiskStation Manager (DSM).");

  script_tag(name:"affected", value:"Synology DSM version 6.2.x prior to 6.2.4-25556-6, 7.0.x prior
  to 7.0.1-42218-4 and 7.1.x prior to 7.1-42661-1.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.4-25556-6, 7.0.1-42218-4,
  7.1-42661-1 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_06");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (version =~ "^6\.2\.4-25556" && (revcomp(a: version, b: "6.2.4-25556-6") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4-25556-6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.0\.1-42218" && (revcomp(a: version, b: "7.0.1-42218-4") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1-42218-4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.1-42661" && (revcomp(a: version, b: "7.1-42661-1") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1-42661-1");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170228
if ((version =~ "^6\.2" && (revcomp(a: version, b: "6.2.4-25556") < 0)) ||
    (version =~ "^7\.0" && (revcomp(a: version, b: "7.0.1-42218") < 0)) ||
    (version =~ "^7\.1" && (revcomp(a: version, b: "7.1-42661") < 0)))
  exit(0);

exit(99);
