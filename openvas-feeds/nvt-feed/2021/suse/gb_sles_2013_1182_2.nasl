# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1182.2");
  script_cve_id("CVE-2013-0160", "CVE-2013-1774", "CVE-2013-1979", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1182-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1182-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131182-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:1182-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to 3.0.82 and to fix various bugs and security issues.

The following security issues have been fixed:

 *

 CVE-2013-1774: The chase_port function in drivers/usb/serial/io_ti.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and system crash) via an attempted /dev/ttyUSB read or write operation on a disconnected Edgeport USB serial converter.

 *

 CVE-2013-0160: Timing side channel on attacks were possible on /dev/ptmx that could allow local attackers to predict keypresses like e.g. passwords. This has been fixed again by updating accessed/modified time on the pty devices in resolution of 8 seconds, so that idle time detection can still work.

 *

 CVE-2013-3222: The vcc_recvmsg function in net/atm/common.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3223: The ax25_recvmsg function in net/ax25/af_ax25.c in the Linux kernel did not initialize a certain data structure, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3224: The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the Linux kernel did not properly initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3225: The rfcomm_sock_recvmsg function in net/bluetooth/rfcomm/sock.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3227: The caif_seqpkt_recvmsg function in net/caif/caif_socket.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3228: The irda_recvmsg_dgram function in net/irda/af_irda.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3229: The iucv_sock_recvmsg function in net/iucv/af_iucv.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3231: The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise High Availability Extension 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.82~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.2_04_3.0.82_0.7~0.9.3", rls:"SLES11.0SP3"))) {
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
