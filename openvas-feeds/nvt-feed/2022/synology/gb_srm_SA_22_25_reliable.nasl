# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127289");
  script_version("2024-03-15T15:36:48+0000");
  script_tag(name:"last_modification", value:"2024-03-15 15:36:48 +0000 (Fri, 15 Mar 2024)");
  # nb: This was initially a single VT but had to be split into two VTs in 2023. The original date
  # for both (the new and the old one) has been kept in this case.
  script_tag(name:"creation_date", value:"2022-12-22 08:49:11 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 15:09:00 +0000 (Thu, 25 May 2023)");

  script_cve_id("CVE-2022-43932", "CVE-2023-0077", "CVE-2023-32955", "CVE-2023-32956");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) 1.2.x < 1.2.5-8227-6, 1.3.x < 1.3.1-9346-3 Multiple Vulnerabilities (Synology-SA-22:25) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-43932: Improper neutralization of special elements in output used by a downstream
  component in CGI component allows remote attackers to read arbitrary files via unspecified
  vectors.

  - CVE-2023-0077: Integer overflow or wraparound vulnerability in CGI component allows remote
  attackers to overflow buffers via unspecified vectors.

  - CVE-2023-32955: Improper neutralization of special elements used in an OS command ('OS Command
  Injection') vulnerability in DHCP Client Functionality allows man-in-the-middle attackers to
  execute arbitrary commands via unspecified vectors.

  - CVE-2023-32956: Improper neutralization of special elements used in an OS command ('OS Command
  Injection') vulnerability in CGI component allows remote attackers to execute arbitrary code via
  unspecified vectors.");

  script_tag(name:"affected", value:"SRM version 1.2.x prior to 1.2.5-8227-6
  and 1.3.x prior to 1.3.1-9346-3.");

  script_tag(name:"solution", value:"Update to firmware version 1.2.5-8227-6, 1.3.1-9346-3 or
  later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_25");

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
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.5-8227-6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^1\.3" && (revcomp(a: version, b: "1.3.1-9346") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-3");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.114438
if (version =~ "^1\.2\.5-8227" || version =~ "^1\.3\.1-9346")
  exit(0);

exit(99);
