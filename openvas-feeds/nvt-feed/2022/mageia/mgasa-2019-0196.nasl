# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0196");
  script_cve_id("CVE-2019-10142", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11833", "CVE-2019-5599");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-07 15:39:56 +0000 (Wed, 07 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0196");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0196.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24840");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24973");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.120");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.121");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.122");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.123");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.124");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.125");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.126");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.127");
  script_xref(name:"URL", value:"https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-001.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2019-0196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on the upstream 4.14.127 and fixes at least
the following security issues:

Jonathan Looney discovered that it is possible to send a crafted sequence
of SACKs which will fragment the RACK send map. An attacker may be able to
further exploit the fragmented send map to cause an expensive linked-list
walk for subsequent SACKs received for that same TCP connection
(CVE-2019-5599).

A flaw was found in the Linux kernel's freescale hypervisor manager
implementation. A parameter passed via to an ioctl was incorrectly
validated and used in size calculations for the page size calculation.
An attacker can use this flaw to crash the system or corrupt memory
or, possibly, create other adverse security affects (CVE-2019-10142).

Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value
was subject to an integer overflow in the Linux kernel when handling TCP
Selective Acknowledgments (SACKs). A remote attacker could use this to
cause a denial of service (CVE-2019-11477).

Jonathan Looney discovered that the TCP retransmission queue implementation
in tcp_fragment in the Linux kernel could be fragmented when handling
certain TCP Selective Acknowledgment (SACK) sequences. A remote attacker
could use this to cause a denial of service (CVE-2019-11478).

Jonathan Looney discovered that the Linux kernel default MSS is hard-coded
to 48 bytes. This allows a remote peer to fragment TCP resend queues
significantly more than if a larger MSS were enforced. A remote attacker
could use this to cause a denial of service (CVE-2019-11479).

fs/ext4/extents.c in the Linux kernel through 5.1.2 does not zero out
the unused memory region in the extent tree block, which might allow
local users to obtain sensitive information by reading uninitialized
data in the filesystem (CVE-2019-11833).

It also fixes an upstream regression that caused older 'legacy'
bluetooth adapters to stop working (mga #24840).

WireGuard has been updated to 0.0.20190601.

For other uptstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.14.127~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.14.127-1.mga6", rpm:"kernel-tmb-desktop-4.14.127-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.14.127-1.mga6", rpm:"kernel-tmb-desktop-devel-4.14.127-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.14.127~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.14.127~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.14.127-1.mga6", rpm:"kernel-tmb-source-4.14.127-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.14.127~1.mga6", rls:"MAGEIA6"))) {
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
