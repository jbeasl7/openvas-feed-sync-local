# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3797.1");
  script_cve_id("CVE-2021-35550", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35586", "CVE-2021-35588", "CVE-2021-35603");
  script_tag(name:"creation_date", value:"2021-11-25 03:26:07 +0000 (Thu, 25 Nov 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-25 19:10:05 +0000 (Mon, 25 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3797-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213797-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191914");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-November/009773.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2021:3797-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:


Update to OpenJDK 7u321 (October 2021 CPU):

- CVE-2021-35550: Fixed weak ciphers preferred over stronger ones for TLS (bsc#1191901).
- CVE-2021-35556: Fixed excessive memory allocation in RTFParser (bsc#1191910).
- CVE-2021-35559: Fixed excessive memory allocation in RTFReader (bsc#1191911).
- CVE-2021-35561: Fixed excessive memory allocation in HashMap and HashSet (bsc#1191912).
- CVE-2021-35564: Fixed certificates with end dates too far in the future can corrupt keystore (bsc#1191913).
- CVE-2021-35565: Fixed loop in HttpsServer triggered during TLS session close (bsc#1191909).
- CVE-2021-35586: Fixed excessive memory allocation in BMPImageReader (bsc#1191914).
- CVE-2021-35588: Fixed incomplete validation of inner class references in ClassFileParser (bsc#1191905)
- CVE-2021-35603: Fixed non-constant comparison during TLS handshakes (bsc#1191906).");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.321~43.53.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.321~43.53.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.321~43.53.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.321~43.53.2", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.321~43.53.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.321~43.53.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.321~43.53.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.321~43.53.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.321~43.53.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.321~43.53.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.321~43.53.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.321~43.53.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.321~43.53.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.321~43.53.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.321~43.53.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.321~43.53.2", rls:"SLES12.0SP5"))) {
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
