# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.61011020994010295");
  script_cve_id("CVE-2025-6019");
  script_tag(name:"creation_date", value:"2025-06-23 04:14:10 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-06-23T05:41:09+0000");
  script_tag(name:"last_modification", value:"2025-06-23 05:41:09 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-19 12:15:19 +0000 (Thu, 19 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-6ef0c40f95)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6ef0c40f95");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6ef0c40f95");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'udisks2' package(s) announced via the FEDORA-2025-6ef0c40f95 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Harden temporary private mounts (#2373301)");

  script_tag(name:"affected", value:"'udisks2' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"libudisks2", rpm:"libudisks2~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-debuginfo", rpm:"libudisks2-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-devel", rpm:"libudisks2-devel~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2", rpm:"udisks2~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-btrfs", rpm:"udisks2-btrfs~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-btrfs-debuginfo", rpm:"udisks2-btrfs-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-debuginfo", rpm:"udisks2-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-debugsource", rpm:"udisks2-debugsource~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-iscsi", rpm:"udisks2-iscsi~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-iscsi-debuginfo", rpm:"udisks2-iscsi-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lsm", rpm:"udisks2-lsm~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lsm-debuginfo", rpm:"udisks2-lsm-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lvm2", rpm:"udisks2-lvm2~2.10.90~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lvm2-debuginfo", rpm:"udisks2-lvm2-debuginfo~2.10.90~3.fc42", rls:"FC42"))) {
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
