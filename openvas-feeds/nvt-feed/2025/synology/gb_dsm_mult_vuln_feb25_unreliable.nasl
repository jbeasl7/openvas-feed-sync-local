# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171235");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-24 19:43:26 +0000 (Mon, 24 Feb 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_cve_id("CVE-2024-10444", "CVE-2025-1021");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) Multiple Vulnerabilities (Synology-SA-25:01, Synology-SA-25:03) - Unreliable Remote Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"- CVE-2024-10444 / Synology-SA-25:01: A vulnerability allows
  man-in-the-middle attackers to hijack the authentication of administrators via unspecified
  vectors.

  - CVE-2025-1021 / Synology-SA-25:03: A vulnerability allows attackers to read any file via
  writable Network File System (NFS) service.");

  script_tag(name:"affected", value:"Synology DSM prior to version 7.1.1-42962-8, 7.2.x prior to
  7.2.1-69057-7 and 7.2.2 prior to 7.2.2-72806-3.");

  script_tag(name:"solution", value:"Update to version 7.1.1-42962-8, 7.2.1-69057-7, 7.2.2-72806-3
  or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_25_01");
  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_25_03");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (version =~ "^7\.1\.1-42962" && revcomp(a: version, b: "7.1.1-42962-8") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1-42962-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.1-69057" && revcomp(a: version, b: "7.2.1-69057-7") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1-69057-7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.2-72806" && (revcomp(a: version, b: "7.2.2-72806-3") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2-72806-3");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.171234
if ((revcomp(a: version, b: "6.2.4-25556") < 0) ||
    (version =~ "^7\.[01]" && (revcomp(a: version, b: "7.1.1-42962") < 0)) ||
    (version =~ "^7\.2" && (revcomp(a: version, b: "7.2.1-69057") < 0)) ||
    (version =~ "^7\.2\.2" && (revcomp(a: version, b: "7.2.2-72806") < 0)))
  exit(0);

exit(99);
