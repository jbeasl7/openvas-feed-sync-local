# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0054.1");
  script_cve_id("CVE-2017-13765", "CVE-2017-13766", "CVE-2017-13767", "CVE-2017-15191", "CVE-2017-15192", "CVE-2017-15193", "CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085", "CVE-2017-9617", "CVE-2017-9766");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-17 20:01:48 +0000 (Tue, 17 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0054-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180054-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070727");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003581.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:0054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark to version 2.2.11 fixes several issues.

These security issues were fixed:

- CVE-2017-13767: The MSDP dissector could have gone into an infinite loop.
 This was addressed by adding length validation (bsc#1056248)
- CVE-2017-13766: The Profinet I/O dissector could have crash with an
 out-of-bounds write. This was addressed by adding string validation
 (bsc#1056249)
- CVE-2017-13765: The IrCOMM dissector had a buffer over-read and application
 crash. This was addressed by adding length validation (bsc#1056251)
- CVE-2017-9766: PROFINET IO data with a high recursion depth allowed remote
 attackers to cause a denial of service (stack exhaustion) in the
 dissect_IODWriteReq function (bsc#1045341)
- CVE-2017-9617: Deeply nested DAAP data may have cause stack exhaustion
 (uncontrolled recursion) in the dissect_daap_one_tag function in the DAAP
 dissector (bsc#1044417)
- CVE-2017-15192: The BT ATT dissector could crash. This was addressed
 in epan/dissectors/packet-btatt.c by considering a case where not all
 of the BTATT packets have the same encapsulation level. (bsc#1062645)
- CVE-2017-15193: The MBIM dissector could crash or exhaust system
 memory. This was addressed in epan/dissectors/packet-mbim.c by changing
 the memory-allocation approach. (bsc#1062645)
- CVE-2017-15191: The DMP dissector could crash. This was addressed in
 epan/dissectors/packet-dmp.c by validating a string length. (bsc#1062645)
- CVE-2017-17083: NetBIOS dissector could crash. This was addressed in
 epan/dissectors/packet-netbios.c by ensuring that write operations are
 bounded by the beginning of a buffer. (bsc#1070727)
- CVE-2017-17084: IWARP_MPA dissector could crash. This was addressed
 in epan/dissectors/packet-iwarp-mpa.c by validating a ULPDU
 length. (bsc#1070727)
- CVE-2017-17085: the CIP Safety dissector could crash. This was
 addressed in epan/dissectors/packet-cipsafety.c by validating the packet
 length. (bsc#1070727)");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsmi", rpm:"libsmi~0.4.5~2.7.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"portaudio", rpm:"portaudio~19~234.18.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.11~40.14.5", rls:"SLES11.0SP4"))) {
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
