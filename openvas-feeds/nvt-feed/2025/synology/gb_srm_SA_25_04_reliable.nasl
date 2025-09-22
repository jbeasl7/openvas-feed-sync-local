# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154199");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-17 03:00:56 +0000 (Mon, 17 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-29843", "CVE-2025-29844", "CVE-2025-29845", "CVE-2025-29846");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) 1.3.x Multiple Vulnerabilities (Synology_SA_25_04) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities allow remote authenticated users to
  read or write non-sensitive files.");

  script_tag(name:"affected", value:"SRM version 1.3.x prior to 1.3.1-9346-13.");

  script_tag(name:"solution", value:"Update to version 1.3.1-9346-13 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_25_04");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 1.1.5-6542-4 and not 1.1.5-6542), there will be 2 VTs with different qod_type.
if (version =~ "^1\.3" && (revcomp(a: version, b: "1.3.1-9346") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-13");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.154198
if (version =~ "^1\.3\.1-9346")
  exit(0);

exit(99);
