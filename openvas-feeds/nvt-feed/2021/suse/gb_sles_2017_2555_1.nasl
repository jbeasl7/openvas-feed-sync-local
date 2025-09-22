# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2555.1");
  script_cve_id("CVE-2017-13765", "CVE-2017-13766", "CVE-2017-13767", "CVE-2017-9617", "CVE-2017-9766");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 18:49:56 +0000 (Thu, 31 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2555-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172555-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056251");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003258.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2017:2555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark to version 2.2.9 fixes several issues.

These security issues were fixed:

- CVE-2017-13767: The MSDP dissector could have gone into an infinite loop.
 This was addressed by adding length validation (bsc#1056248).
- CVE-2017-13766: The Profinet I/O dissector could have crash with an
 out-of-bounds write. This was addressed by adding string validation
 (bsc#1056249).
- CVE-2017-13765: The IrCOMM dissector had a buffer over-read and application
 crash. This was addressed by adding length validation (bsc#1056251).
- CVE-2017-9766: PROFINET IO data with a high recursion depth allowed remote
 attackers to cause a denial of service (stack exhaustion) in the
 dissect_IODWriteReq function (bsc#1045341).
- CVE-2017-9617: Deeply nested DAAP data may have cause stack exhaustion
 (uncontrolled recursion) in the dissect_daap_one_tag function in the DAAP
 dissector (bsc#1044417).");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.9~48.9.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.9~48.9.2", rls:"SLES12.0SP3"))) {
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
