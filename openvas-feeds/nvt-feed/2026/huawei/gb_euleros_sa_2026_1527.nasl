# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1527");
  script_cve_id("CVE-2025-12748", "CVE-2025-13193");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-17 17:15:47 +0000 (Mon, 17 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for libvirt (EulerOS-SA-2026-1527)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1527");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1527");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libvirt' package(s) announced via the EulerOS-SA-2026-1527 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in libvirt in the XML file processing. More specifically, the parsing of user provided XML files was performed before the ACL checks. A malicious user with limited permissions could exploit this flaw by submitting a specially crafted XML file, causing libvirt to allocate too much memory on the host. The excessive memory consumption could lead to a libvirt process crash on the host, resulting in a denial-of-service condition.(CVE-2025-12748)

A flaw was found in libvirt. External inactive snapshots for shut-down VMs are incorrectly created as world-readable, making it possible for unprivileged users to inspect the guest OS contents. This results in an information disclosure vulnerability.(CVE-2025-13193)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

if(release == "EULEROSVIRT-2.12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin", rpm:"libvirt-admin~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-bash-completion", rpm:"libvirt-bash-completion~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core", rpm:"libvirt-daemon-driver-storage-core~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk", rpm:"libvirt-daemon-driver-storage-disk~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi", rpm:"libvirt-daemon-driver-storage-iscsi~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical", rpm:"libvirt-daemon-driver-storage-logical~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath", rpm:"libvirt-daemon-driver-storage-mpath~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi", rpm:"libvirt-daemon-driver-storage-scsi~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs", rpm:"libvirt-libs~6.2.0~2.12.0.5.660", rls:"EULEROSVIRT-2.12.0"))) {
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
