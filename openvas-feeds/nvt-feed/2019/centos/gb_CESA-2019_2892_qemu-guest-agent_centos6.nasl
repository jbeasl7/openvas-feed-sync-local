# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883114");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2018-10839", "CVE-2018-11806", "CVE-2018-17962", "CVE-2019-6778", "CVE-2019-12155");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:15:00 +0000 (Thu, 10 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-10-01 02:00:49 +0000 (Tue, 01 Oct 2019)");
  script_name("CentOS Update for qemu-guest-agent CESA-2019:2892 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:2892");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-September/023454.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-guest-agent'
  package(s) announced via the CESA-2019:2892 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a full virtualization solution for
Linux on a variety of architectures. The qemu-kvm packages provide the
user-space component for running virtual machines that use KVM.

Security Fix(es):

  * QEMU: slirp: heap buffer overflow while reassembling fragmented datagrams
(CVE-2018-11806)

  * QEMU: slirp: heap buffer overflow in tcp_emu() (CVE-2019-6778)

  * QEMU: ne2000: integer overflow leads to buffer overflow issue
(CVE-2018-10839)

  * QEMU: pcnet: integer overflow leads to buffer overflow (CVE-2018-17962)

  * QEMU: qxl: null pointer dereference while releasing spice resources
(CVE-2019-12155)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'qemu-guest-agent' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.506.el6_10.5", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.506.el6_10.5", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.506.el6_10.5", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.506.el6_10.5", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
