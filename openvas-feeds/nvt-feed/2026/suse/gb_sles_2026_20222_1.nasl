# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20222.1");
  script_cve_id("CVE-2025-11626", "CVE-2025-13499", "CVE-2025-13945", "CVE-2025-13946", "CVE-2025-9817", "CVE-2026-0959", "CVE-2026-0961", "CVE-2026-0962");
  script_tag(name:"creation_date", value:"2026-02-09 04:44:52 +0000 (Mon, 09 Feb 2026)");
  script_version("2026-02-09T06:03:20+0000");
  script_tag(name:"last_modification", value:"2026-02-09 06:03:20 +0000 (Mon, 09 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-09 19:20:23 +0000 (Thu, 09 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20222-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620222-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256739");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024065.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-4.4.13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2026:20222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

Update to Wireshark 4.4.13:

- CVE-2025-11626: MONGO dissector infinite loop (bsc#1251933).
- CVE-2025-13499: Kafka dissector crash (bsc#1254108).
- CVE-2025-13945: HTTP3 dissector crash (bsc#1254471).
- CVE-2025-13946: MEGACO dissector infinite loop (bsc#1254472).
- CVE-2025-9817: SSH dissector crash (bsc#1249090).
- CVE-2026-0959: IEEE 802.11 dissector crash (bsc#1256734).
- CVE-2026-0961: BLF file parser crash (bsc#1256738).
- CVE-2026-0962: SOME/IP-SD dissector crash (bsc#1256739).

Full changelog:

[link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark18", rpm:"libwireshark18~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap15", rpm:"libwiretap15~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil16", rpm:"libwsutil16~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~4.4.13~160000.1.1", rls:"SLES16.0.0"))) {
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
