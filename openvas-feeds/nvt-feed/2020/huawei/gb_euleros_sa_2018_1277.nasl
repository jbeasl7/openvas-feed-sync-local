# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1277");
  script_cve_id("CVE-2018-5748", "CVE-2018-6764");
  script_tag(name:"creation_date", value:"2020-01-23 11:19:52 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-18 11:03:10 +0000 (Sun, 18 Mar 2018)");

  script_name("Huawei EulerOS: Security Advisory for libvirt (EulerOS-SA-2018-1277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1277");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2018-1277");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libvirt' package(s) announced via the EulerOS-SA-2018-1277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"util/virlog.c in libvirt does not properly determine the hostname on LXC container startup, which allows local guest OS users to bypass an intended container protection mechanism and execute arbitrary commands via a crafted NSS module.(CVE-2018-6764)

qemu/qemu_monitor.c in libvirt allows attackers to cause a denial of service (memory consumption) via a large QEMU reply.(CVE-2018-5748)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Huawei EulerOS Virtualization 2.5.0.");

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

if(release == "EULEROSVIRT-2.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~1.3.4~62", rls:"EULEROSVIRT-2.5.0"))) {
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
