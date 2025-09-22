# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2891.1");
  script_cve_id("CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 14:13:43 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2891-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182891-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106514");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004611.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.4.9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:2891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark to version 2.4.9 fixes the following issues:

Wireshark was updated to 2.4.9 (bsc#1094301, bsc#1106514).

Security issues fixed:

- CVE-2018-16058: Bluetooth AVDTP dissector crash (wnpa-sec-2018-44)
- CVE-2018-16056: Bluetooth Attribute Protocol dissector crash (wnpa-sec-2018-45)
- CVE-2018-16057: Radiotap dissector crash (wnpa-sec-2018-46)
- CVE-2018-11355: Fix RTCP dissector crash (bsc#1094301).
- CVE-2018-14370: IEEE 802.11 dissector crash (wnpa-sec-2018-43, bsc#1101802)
- CVE-2018-14368: Bazaar dissector infinite loop (wnpa-sec-2018-40, bsc#1101794)
- CVE-2018-11362: Fix LDSS dissector crash (bsc#1094301).
- CVE-2018-11361: Fix IEEE 802.11 dissector crash (bsc#1094301).
- CVE-2018-11360: Fix GSM A DTAP dissector crash (bsc#1094301).
- CVE-2018-14342: BGP dissector large loop (wnpa-sec-2018-34, bsc#1101777)
- CVE-2018-14343: ASN.1 BER dissector crash (wnpa-sec-2018-37, bsc#1101786)
- CVE-2018-14340: Multiple dissectors could crash (wnpa-sec-2018-36, bsc#1101804)
- CVE-2018-14341: DICOM dissector crash (wnpa-sec-2018-39, bsc#1101776)
- CVE-2018-11358: Fix Q.931 dissector crash (bsc#1094301).
- CVE-2018-14344: ISMP dissector crash (wnpa-sec-2018-35, bsc#1101788)
- CVE-2018-11359: Fix multiple dissectors crashs (bsc#1094301).
- CVE-2018-11356: Fix DNS dissector crash (bsc#1094301).
- CVE-2018-14339: MMSE dissector infinite loop (wnpa-sec-2018-38, bsc#1101810)
- CVE-2018-11357: Fix multiple dissectors that could consume excessive memory (bsc#1094301).
- CVE-2018-14367: CoAP dissector crash (wnpa-sec-2018-42, bsc#1101791)
- CVE-2018-11354: Fix IEEE 1905.1a dissector crash (bsc#1094301).
- CVE-2018-14369: HTTP2 dissector crash (wnpa-sec-2018-41, bsc#1101800)

Further bug fixes and updated protocol support as listed in:
 [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.9~48.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.9~48.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.9~48.29.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.4.9~48.29.1", rls:"SLES12.0SP3"))) {
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
