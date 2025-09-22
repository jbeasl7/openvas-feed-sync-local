# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833524");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-26555", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6546", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6622", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:15:07 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:49:58 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:0129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0129-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JPF4IYSK7ELMB7RFV43FYIYKLMYRMQ7F");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:0129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix
      garbage collector's deletion of SKB races with unix_stream_read_generic() on
      the socket that the SKB is queued on (bsc#1218447).

  * CVE-2023-6610: Fixed an out of bounds read in the SMB client when printing
      debug information (bsc#1217946).

  * CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race
      condition in bt_sock_recvmsg (bsc#1218559).

  * CVE-2020-26555: Fixed an issue during BR/EDR PIN code pairing in the
      Bluetooth subsystem that would allow replay attacks (bsc#1179610
      bsc#1215237).

  * CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving
      a malformed length from a server (bsc#1217947).

  * CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via
      the GSMIOC_SETCONF ioctl that could lead to local privilege escalation
      (bsc#1218335).

  * CVE-2023-6931: Fixed a heap out-of-bounds write vulnerability in the Linux
      kernel's Performance Events system component that could lead to local
      privilege escalation. (bsc#1218258).

  * CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's
      ipv4: igmp component that could lead to local privilege escalation
      (bsc#1218253).

  * CVE-2023-6622: Fixed a null pointer dereference vulnerability in
      nft_dynset_init() that could allow a local attacker with CAP_NET_ADMIN user
      privilege to trigger a denial of service (bsc#1217938).

  * CVE-2023-6121: Fixed an information leak via dmesg when receiving a crafted
      packet in the NVMe-oF/TCP subsystem (bsc#1217250).

  The following non-security bugs were fixed:

  * Reviewed and added more information to README.SUSE (jsc#PED-5021).

  * Build in the correct KOTD repository with multibuild (JSC-SLE#5501,
      boo#1211226, bsc#1218184) With multibuild setting repository flags is no
      longer supported for individual spec files - see
      conditional that depends on a macro set up by bs-upload-kernel instead. With
      that each package should build only in one repository - either standard or
      QA. Note: bs-upload-kernel does not interpret rpm conditionals, and only
      uses the first ExclusiveArch line to determine the architectures to enable.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.65.1", rls:"openSUSELeapMicro5.4"))) {
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
