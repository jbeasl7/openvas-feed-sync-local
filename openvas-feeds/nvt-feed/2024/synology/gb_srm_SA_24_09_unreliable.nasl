# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153160");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-09-23 03:54:59 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-04 19:07:26 +0000 (Mon, 04 Aug 2025)");

  script_cve_id("CVE-2024-53279", "CVE-2024-53280", "CVE-2024-53281", "CVE-2024-53282",
                "CVE-2024-53283", "CVE-2024-53284", "CVE-2024-53285");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) 1.3.x Multiple Vulnerabilities (Synology-SA-24:09) - Unreliable Remote Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-53279: XSS in file station functionality

  - CVE-2024-53280: XSS in network center policy route functionality

  - CVE-2024-53281: XSS in network WOL functionality

  - CVE-2024-53282: XSS in WiFi connect MAC filter functionality

  - CVE-2024-53283: XSS in router port forward functionality

  - CVE-2024-53284: XSS in WiFi connect setting functionality

  - CVE-2024-53285: XSS in DDNS record functionality");

  script_tag(name:"affected", value:"SRM version 1.3.x prior to 1.3.1-9346-10.");

  script_tag(name:"solution", value:"Update to version 1.3.1-9346-10 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_09");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 1.1.5-6542-4 and not 1.1.5-6542), there will be 2 VTs with different qod_type.
if (version =~ "^1\.3\.1-9346" && (revcomp(a: version, b: "1.3.1-9346-10") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-10");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.153159
if (version =~ "^1\.3" && (revcomp(a: version, b: "1.3.1-9346") < 0))
  exit(0);

exit(99);
