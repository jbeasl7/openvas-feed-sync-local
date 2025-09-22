# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0585.1");
  script_cve_id("CVE-2013-7446", "CVE-2015-0272", "CVE-2015-5707", "CVE-2015-7550", "CVE-2015-7799", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8660", "CVE-2015-8767", "CVE-2015-8785", "CVE-2016-0723", "CVE-2016-2069");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 17:31:24 +0000 (Mon, 18 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0585-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160585-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/855062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965840");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-February/001895.html");
  script_xref(name:"URL", value:"https://lkml.org/lkml/2016/2/4/618");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:0585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.53 to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in the Linux kernel allowed local users to bypass intended AF_UNIX socket permissions or cause a denial of service (panic) via crafted epoll_ctl calls (bnc#955654).
- CVE-2015-5707: Integer overflow in the sg_start_req function in drivers/scsi/sg.c in the Linux kernel allowed local users to cause a denial of service or possibly have unspecified other impact via a large iov_count value in a write request (bnc#940338).
- CVE-2015-7550: The keyctl_read_key function in security/keys/keyctl.c in the Linux kernel did not properly use a semaphore, which allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted application that leverages a race condition between keyctl_revoke and keyctl_read calls (bnc#958951).
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the Linux kernel did not ensure that certain slot numbers are valid, which allowed local users to cause a denial of service (NULL pointer dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call (bnc#949936).
- CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in the Linux kernel did not validate attempted changes to the MTU value, which allowed context-dependent attackers to cause a denial of service (packet loss) via a value that was (1) smaller than the minimum compliant value or (2) larger than the MTU of an interface, as demonstrated by a Router Advertisement (RA) message that is not validated by a daemon, a different vulnerability than CVE-2015-0272 (bnc#955354).
- CVE-2015-8539: The KEYS subsystem in the Linux kernel allowed local users to gain privileges or cause a denial of service (BUG) via crafted keyctl commands that negatively instantiate a key, related to security/keys/encrypted-keys/encrypted.c, security/keys/trusted.c, and security/keys/user_defined.c (bnc#958463).
- CVE-2015-8543: The networking implementation in the Linux kernel did not validate protocol identifiers for certain protocol families, which allowed local users to cause a denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application (bnc#958886).
- CVE-2015-8550: Optimizations introduced by the compiler could have lead to double fetch vulnerabilities, potentially possibly leading to arbitrary code execution in backend (bsc#957988).
- CVE-2015-8551: Xen PCI backend driver did not perform proper sanity checks on the device's state, allowing for DoS (bsc#957990).
- CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect functions in drivers/net/ppp/pptp.c in the Linux kernel did not verify an address ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.53~60.30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.53~60.30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.53~60.30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.53~60.30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.53~60.30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.53~60.30.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.53~60.30.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.7.0~3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.7.0_k3.12.53_60.30~3.1", rls:"SLES12.0SP1"))) {
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
