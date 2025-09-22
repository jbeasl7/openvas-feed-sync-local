# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9710279897269699");
  script_cve_id("CVE-2025-6019");
  script_tag(name:"creation_date", value:"2025-06-23 04:14:10 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-06-23T05:41:09+0000");
  script_tag(name:"last_modification", value:"2025-06-23 05:41:09 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-19 12:15:19 +0000 (Thu, 19 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-af7ba2696c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-af7ba2696c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-af7ba2696c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373715");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libblockdev' package(s) announced via the FEDORA-2025-af7ba2696c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libblockdev-3.3.1-1.fc42.

##### **Changelog for libblockdev**

```
* Wed Jun 18 2025 Packit <hello@packit.dev> - 3.3.1-1
- Update to version 3.3.1

```");

  script_tag(name:"affected", value:"'libblockdev' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"libblockdev", rpm:"libblockdev~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-btrfs", rpm:"libblockdev-btrfs~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-btrfs-debuginfo", rpm:"libblockdev-btrfs-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-btrfs-devel", rpm:"libblockdev-btrfs-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-crypto", rpm:"libblockdev-crypto~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-crypto-debuginfo", rpm:"libblockdev-crypto-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-crypto-devel", rpm:"libblockdev-crypto-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-debuginfo", rpm:"libblockdev-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-debugsource", rpm:"libblockdev-debugsource~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-devel", rpm:"libblockdev-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-dm", rpm:"libblockdev-dm~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-dm-debuginfo", rpm:"libblockdev-dm-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-dm-devel", rpm:"libblockdev-dm-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-fs", rpm:"libblockdev-fs~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-fs-debuginfo", rpm:"libblockdev-fs-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-fs-devel", rpm:"libblockdev-fs-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-loop", rpm:"libblockdev-loop~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-loop-debuginfo", rpm:"libblockdev-loop-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-loop-devel", rpm:"libblockdev-loop-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm", rpm:"libblockdev-lvm~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm-dbus", rpm:"libblockdev-lvm-dbus~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm-dbus-debuginfo", rpm:"libblockdev-lvm-dbus-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm-dbus-devel", rpm:"libblockdev-lvm-dbus-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm-debuginfo", rpm:"libblockdev-lvm-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-lvm-devel", rpm:"libblockdev-lvm-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mdraid", rpm:"libblockdev-mdraid~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mdraid-debuginfo", rpm:"libblockdev-mdraid-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mdraid-devel", rpm:"libblockdev-mdraid-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mpath", rpm:"libblockdev-mpath~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mpath-debuginfo", rpm:"libblockdev-mpath-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-mpath-devel", rpm:"libblockdev-mpath-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvdimm", rpm:"libblockdev-nvdimm~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvdimm-debuginfo", rpm:"libblockdev-nvdimm-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvdimm-devel", rpm:"libblockdev-nvdimm-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvme", rpm:"libblockdev-nvme~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvme-debuginfo", rpm:"libblockdev-nvme-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-nvme-devel", rpm:"libblockdev-nvme-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-part", rpm:"libblockdev-part~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-part-debuginfo", rpm:"libblockdev-part-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-part-devel", rpm:"libblockdev-part-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-plugins-all", rpm:"libblockdev-plugins-all~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-s390", rpm:"libblockdev-s390~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-s390-debuginfo", rpm:"libblockdev-s390-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-s390-devel", rpm:"libblockdev-s390-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smart", rpm:"libblockdev-smart~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smart-debuginfo", rpm:"libblockdev-smart-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smart-devel", rpm:"libblockdev-smart-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smartmontools", rpm:"libblockdev-smartmontools~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smartmontools-debuginfo", rpm:"libblockdev-smartmontools-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-smartmontools-devel", rpm:"libblockdev-smartmontools-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-swap", rpm:"libblockdev-swap~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-swap-debuginfo", rpm:"libblockdev-swap-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-swap-devel", rpm:"libblockdev-swap-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-tools", rpm:"libblockdev-tools~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-tools-debuginfo", rpm:"libblockdev-tools-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-utils", rpm:"libblockdev-utils~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-utils-debuginfo", rpm:"libblockdev-utils-debuginfo~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-utils-devel", rpm:"libblockdev-utils-devel~3.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-blockdev", rpm:"python3-blockdev~3.3.1~1.fc42", rls:"FC42"))) {
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
