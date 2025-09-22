# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885548");
  script_cve_id("CVE-2023-49933", "CVE-2023-49934", "CVE-2023-49935", "CVE-2023-49936", "CVE-2023-49937", "CVE-2023-49938");
  script_tag(name:"creation_date", value:"2024-01-18 09:13:58 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:17:34 +0000 (Thu, 21 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-9a74d212f8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9a74d212f8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9a74d212f8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155310");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254496");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254499");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254502");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254505");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254507");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254509");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm' package(s) announced via the FEDORA-2023-9a74d212f8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to 22.05.11
- Closes CVE-2023-49933 through CVE-2023-49938");

  script_tag(name:"affected", value:"'slurm' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"slurm", rpm:"slurm~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-contribs", rpm:"slurm-contribs~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debuginfo", rpm:"slurm-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debugsource", rpm:"slurm-debugsource~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-devel", rpm:"slurm-devel~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-doc", rpm:"slurm-doc~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-gui", rpm:"slurm-gui~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-gui-debuginfo", rpm:"slurm-gui-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-libs", rpm:"slurm-libs~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-libs-debuginfo", rpm:"slurm-libs-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-nss_slurm", rpm:"slurm-nss_slurm~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-nss_slurm-debuginfo", rpm:"slurm-nss_slurm-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-openlava", rpm:"slurm-openlava~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm", rpm:"slurm-pam_slurm~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm-debuginfo", rpm:"slurm-pam_slurm-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-perlapi", rpm:"slurm-perlapi~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-perlapi-debuginfo", rpm:"slurm-perlapi-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-rrdtool", rpm:"slurm-rrdtool~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-rrdtool-debuginfo", rpm:"slurm-rrdtool-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmctld", rpm:"slurm-slurmctld~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmctld-debuginfo", rpm:"slurm-slurmctld-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmd", rpm:"slurm-slurmd~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmd-debuginfo", rpm:"slurm-slurmd-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd", rpm:"slurm-slurmdbd~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd-debuginfo", rpm:"slurm-slurmdbd-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmrestd", rpm:"slurm-slurmrestd~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmrestd-debuginfo", rpm:"slurm-slurmrestd-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque", rpm:"slurm-torque~22.05.11~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque-debuginfo", rpm:"slurm-torque-debuginfo~22.05.11~2.fc39", rls:"FC39"))) {
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
