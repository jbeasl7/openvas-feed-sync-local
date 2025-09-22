# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114442");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  # nb: This was initially a single VT but had to be split into two VTs in 2023. The original date
  # for both (the new and the old one) has been kept in this case.
  script_tag(name:"creation_date", value:"2023-11-23 04:07:35 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 07:15:06 +0000 (Fri, 28 Jun 2024)");

  script_cve_id("CVE-2024-39347", "CVE-2024-39348");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) 1.2.x < 1.2.5-8227-11, 1.3.x < 1.3.1-9346-8 Multiple Vulnerabilities (Synology-SA-23:16) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-39347: Incorrect default permissions vulnerability in firewall functionality

  - CVE-2024-39348: Download of code without integrity check vulnerability in AirPrint
  functionality");

  script_tag(name:"impact", value:"The vulnerabilities allow man-in-the-middle attackers to execute
  arbitrary code or access intranet resources via a susceptible version of Synology Router Manager
  (SRM).");

  script_tag(name:"affected", value:"SRM version 1.2.x prior to 1.2.5-8227-11 and
  1.3.x prior to 1.3.1-9346-8.");

  script_tag(name:"solution", value:"Update to firmware version 1.2.5-8227-11, 1.3.1-9346-8 or
  later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_23_16");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 1.1.5-6542-4 and not 1.1.5-6542), there will be 2 VTs with different qod_type.
if (version =~ "^1\.2" && (revcomp(a: version, b: "1.2.5-8227") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.5-8227-11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^1\.3" && (revcomp(a: version, b: "1.3.1-9346") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-8");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.151294
if (version =~ "^1\.2\.5-8227" || version =~ "^1\.3\.1-9346")
  exit(0);

exit(99);
