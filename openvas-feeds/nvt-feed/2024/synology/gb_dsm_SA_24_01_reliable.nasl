# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151501");
  script_version("2024-12-17T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2024-01-10 05:41:07 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) ACE Vulnerability (Synology-SA-24:01) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to an arbitrary
  code execution (ACE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A vulnerability allows local users to execute arbitrary code via
  a susceptible version of Synology DiskStation Manager (DSM).");

  script_tag(name:"affected", value:"Synology DSM prior to version 6.2.4-25556-8, 7.0.x prior to
  7.0.1-42218-7, 7.1.x prior to 7.1.1-42962-7 and 7.2.x prior to 7.2-64561.");

  script_tag(name:"solution", value:"Update to version 6.2.4-25556-8, 7.0.1-42218-7, 7.1.1-42962-7,
  7.2-64561 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_01");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 6.2.4-25556 and not 6.2.4-25556-8), there will be 2 VTs with different qod_type.
if (revcomp(a: version, b: "6.2.4-25556") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4-25556-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.0" && (revcomp(a: version, b: "7.0.1-42218") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1-42218-7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.1" && (revcomp(a: version, b: "7.1.1-42962") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1-42962-7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2" && (revcomp(a: version, b: "7.2-64561") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2-64561");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.171013
if (version =~ "^6\.2\.4-25556" || version =~ "^7\.0\.1-42218" ||
    version =~ "^7\.1\.1-42962")
  exit(0);

exit(99);
