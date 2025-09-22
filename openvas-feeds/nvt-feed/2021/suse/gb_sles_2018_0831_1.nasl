# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0831.1");
  script_cve_id("CVE-2017-15119", "CVE-2017-15124", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18030", "CVE-2017-18043", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:42:19 +0000 (Thu, 10 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0831-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180831-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003848.html");
  script_xref(name:"URL", value:"https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-update/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2018:0831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

This update has the next round of Spectre v2 related patches, which now integrate with corresponding changes in libvirt. (CVE-2017-5715 bsc#1068032)

The January 2018 release of qemu initially addressed the Spectre v2 vulnerability for KVM guests by exposing the spec-ctrl feature for all x86 vcpu types, which was the quick and dirty approach,
but not the proper solution.

We replaced our initial patch by the patches from upstream.

This update defines spec_ctrl and ibpb cpu feature flags as well as new cpu models which are clones of existing models with either -IBRS or -IBPB added to the end of the model name. These new vcpu models explicitly include the new feature(s), whereas the feature flags can be added to the cpu parameter as with other features. In short, for continued Spectre v2 protection, ensure that either the appropriate cpu feature flag is added to the QEMU command-line, or one of the new cpu models is used.

Although migration from older versions is supported, the new cpu features won't be properly exposed to the guest until it is restarted with the cpu features explicitly added. A reboot is insufficient.

A warning patch is added which attempts to detect a migration from a qemu version which had the quick and dirty fix (it only detects certain cases, but hopefully is helpful.)
For additional information on Spectre v2 as it relates to QEMU,
see:
 [link moved to references]

A patch is added to continue to detect Spectre v2 mitigation features (as shown by cpuid), and if found provide that feature to guests, even if running on older KVM (kernel) versions which do not yet expose that feature to QEMU. (bsc#1082276)

These two patches will be removed when we can reasonably assume everyone is running with the appropriate updates.


Also security fixes for the following CVE issues are included:

- CVE-2017-15119: The Network Block Device (NBD) server in Quick Emulator (QEMU), was vulnerable to a denial of service issue. It could occur if a client sent large option requests, making the server waste CPU time on reading up to 4GB per request. A client could use this flaw to keep the NBD server from serving other requests, resulting in DoS. (bsc#1070144)
- CVE-2017-15124: VNC server implementation in Quick Emulator (QEMU) was found to be vulnerable to an unbounded memory allocation issue, as it did not throttle the framebuffer updates sent to its client. If the client did not consume these updates, VNC server allocates growing memory to hold onto this data. A malicious remote VNC client could use this flaw to cause DoS to the server host. (bsc#1073489)
- CVE-2017-16845: The PS2 driver in Qemu did not validate 'rptr' and 'count' values during guest migration, leading to out-of-bounds access. (bsc#1068613)
- CVE-2017-17381: The Virtio Vring implementation in QEMU allowed local OS guest users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~41.37.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~41.37.1", rls:"SLES12.0SP2"))) {
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
