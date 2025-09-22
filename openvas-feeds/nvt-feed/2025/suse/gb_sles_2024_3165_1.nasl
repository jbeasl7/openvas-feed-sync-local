# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3165.1");
  script_cve_id("CVE-2023-0414", "CVE-2023-0666", "CVE-2023-2854", "CVE-2023-3649", "CVE-2023-5371", "CVE-2023-6174", "CVE-2023-6175", "CVE-2024-0207", "CVE-2024-0210", "CVE-2024-0211", "CVE-2024-2955");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-16 18:53:23 +0000 (Wed, 16 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3165-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243165-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222030");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036824.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-4.0.0.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-4.2.0.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2024:3165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

wireshark was updated from version 3.6.23 to version 4.2.6 (jsc#PED-8517):

- Security issues fixed with this update:

 * CVE-2024-0207: HTTP3 dissector crash (bsc#1218503)
 * CVE-2024-0210: Zigbee TLV dissector crash (bsc#1218506)
 * CVE-2024-0211: DOCSIS dissector crash (bsc#1218507)
 * CVE-2023-6174: Fixed SSH dissector crash (bsc#1217247)
 * CVE-2023-6175: NetScreen file parser crash (bsc#1217272)
 * CVE-2023-5371: RTPS dissector memory leak (bsc#1215959)
 * CVE-2023-3649: iSCSI dissector crash (bsc#1213318)
 * CVE-2023-2854: BLF file parser crash (bsc#1211708)
 * CVE-2023-0666: RTPS dissector crash (bsc#1211709)
 * CVE-2023-0414: EAP dissector crash (bsc#1207666)

- Major changes introduced with versions 4.2.0 and 4.0.0:

 * Version 4.2.0 [link moved to references]
 * Version 4.0.0 [link moved to references]

- Added an aditional desktopfile to start wireshark which asks for
 the super user password.");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 15-SP6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark17", rpm:"libwireshark17~4.2.6~150600.18.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap14", rpm:"libwiretap14~4.2.6~150600.18.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil15", rpm:"libwsutil15~4.2.6~150600.18.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~4.2.6~150600.18.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
