# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170271");
  script_version("2024-12-17T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"creation_date", value:"2022-12-14 11:22:34 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-17 16:16:13 +0000 (Thu, 17 Nov 2022)");

  script_cve_id("CVE-2022-45188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) 6.2.x Multiple Vulnerabilities (Synology-SA-22:23) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities reported by PWN2OWN TORONTO 2022 have
  been addressed.

  - Claroty Research was able to execute a chain of 3 bugs (2 missing authentication for
  critical function and an authentication bypass) attack against the Synology DiskStation DS920+

  - ASU SEFCOM was able to execute their OOB Write attack against the Synology DiskStation DS920+ to
  gain code execution");

  script_tag(name:"affected", value:"Synology DSM versions 6.2.x prior to 6.2.4-25556-7.");

  script_tag(name:"solution", value:"Update to version 6.2.4-25556-7 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_23");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2022/12/5/pwn2own-toronto-2022-day-one-results");
  script_xref(name:"URL", value:"https://rushbnt.github.io/bug%20analysis/netatalk-0day/");
  script_xref(name:"URL", value:"https://netatalk.io/3.1/ReleaseNotes3.1.15");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: This is checked by VTs 1.3.6.1.4.1.25623.1.0.170273 and
# 1.3.6.1.4.1.25623.1.0.170293
if (version =~ "^7\.")
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (version =~ "6\.2" && (revcomp(a: version, b: "6.2.4-25556") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4-25556-7");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170504
if (version =~ "^6\.2\.4-25556")
  exit(0);

exit(99);
