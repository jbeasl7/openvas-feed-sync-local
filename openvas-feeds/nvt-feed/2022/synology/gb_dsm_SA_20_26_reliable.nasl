# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170227");
  script_version("2024-03-15T15:36:48+0000");
  script_tag(name:"last_modification", value:"2024-03-15 15:36:48 +0000 (Fri, 15 Mar 2024)");
  # nb: This was initially a single VT but had to be split into two VTs in 2023. The original date
  # for both (the new and the old one) has been kept in this case.
  script_tag(name:"creation_date", value:"2022-11-16 10:31:34 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 13:51:00 +0000 (Wed, 30 Mar 2022)");

  script_cve_id("CVE-2021-26560", "CVE-2021-26561", "CVE-2021-26562", "CVE-2021-26564",
                "CVE-2021-26565", "CVE-2021-26566", "CVE-2021-26567", "CVE-2021-26569",
                "CVE-2021-27646", "CVE-2021-27647", "CVE-2021-27649", "CVE-2021-29083",
                "CVE-2021-29084", "CVE-2021-29085", "CVE-2021-29086", "CVE-2021-29087",
                "CVE-2021-31439", "CVE-2022-22687");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) 6.2.x < 6.2.3-25426-3 Multiple Vulnerabilities (Synology-SA-20:26) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2021-26560, CVE-2021-26561, CVE-2021-26562: Multiple vulnerabilities in
  synoagentregisterd allow man-in-the-middle attackers to spoof servers via an HTTP session or to
  execute arbitrary code via syno_finder_site HTTP header.

  - CVE-2021-26564, CVE-2021-26565, CVE-2021-26566: Multiple vulnerabilities in synorelayd allows
  man-in-the-middle attackers to execute arbitrary commands via inbound QuickConnect traffic, spoof
  servers and obtain sensitive information via an HTTP session.

  - CVE-2021-26567: Stack-based buffer overflow vulnerability in frontend/main.c in faad2 before
  2.2.7.1 allow local attackers to execute arbitrary code via filename and pathname options.

  - CVE-2021-27646, CVE-2021-27647: Multiple vulnerabilities in iscsi_snapshot_comm_core allows remote
  attackers to execute arbitrary code via crafted web requests.

  - CVE-2021-27649: Use after free vulnerability in file transfer protocol component allows remote
  attackers to execute arbitrary code via unspecified vectors.

  - CVE-2021-26564: Cleartext transmission of sensitive information vulnerability in synorelayd allows
  man-in-the-middle attackers to spoof servers via an HTTP session.

  - CVE-2021-26565: Cleartext transmission of sensitive information vulnerability in synorelayd allows
  man-in-the-middle attackers to obtain sensitive information via an HTTP session.

  - CVE-2021-29083: Improper neutralization of special elements used in an OS command in
  SYNO.Core.Network.PPPoE allows remote authenticated users to execute arbitrary code via realname
  parameter.

  - CVE-2021-29084, CVE-2021-29085: Improper neutralization of special elements in Security Advisor
  report management and file sharing management components allows remote attackers to read arbitrary
  files via unspecified vectors.

  - CVE-2021-29086: Exposure of sensitive information vulnerability in webapi.

  - CVE-2021-29087: Path Traversal vulnerability in webapi component.

  - CVE-2021-31439: An attacker can leverage the lack of proper validation of the length of
  user-supplied data prior to copying it to a heap-based buffer, while processing the DSI structures
  in Netatalk, to execute code in the context of the current process.

  - CVE-2022-22687: Buffer copy without checking size of input ('Classic Buffer Overflow')
  vulnerability in Authentication functionality allows remote attackers to execute arbitrary code via
  unspecified vectors.");

  script_tag(name:"affected", value:"Synology DSM version 6.2.x prior to 6.2.3-25426-3.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.3-25426-3 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_20_26");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (version =~ "^6\.2" && (revcomp(a: version, b: "6.2.3-25426") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3-25426-3");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170287
if (version =~ "^6\.2\.3-25426")
  exit(0);

exit(99);
