# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884925");
  script_cve_id("CVE-2023-41915");
  script_tag(name:"creation_date", value:"2023-10-04 01:16:50 +0000 (Wed, 04 Oct 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 14:32:53 +0000 (Wed, 13 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-1185eca900)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1185eca900");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1185eca900");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238898");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239124");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240042");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openmpi, pmix, prrte, slurm' package(s) announced via the FEDORA-2023-1185eca900 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-41915");

  script_tag(name:"affected", value:"'openmpi, pmix, prrte, slurm' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"openmpi", rpm:"openmpi~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-debuginfo", rpm:"openmpi-debuginfo~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-debugsource", rpm:"openmpi-debugsource~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-devel", rpm:"openmpi-devel~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-devel-debuginfo", rpm:"openmpi-devel-debuginfo~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-java", rpm:"openmpi-java~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-java-devel", rpm:"openmpi-java-devel~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix", rpm:"pmix~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-debuginfo", rpm:"pmix-debuginfo~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-debugsource", rpm:"pmix-debugsource~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-devel", rpm:"pmix-devel~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-tools", rpm:"pmix-tools~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-tools-debuginfo", rpm:"pmix-tools-debuginfo~4.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte", rpm:"prrte~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte-debuginfo", rpm:"prrte-debuginfo~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte-debugsource", rpm:"prrte-debugsource~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte-devel", rpm:"prrte-devel~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte-libs", rpm:"prrte-libs~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prrte-libs-debuginfo", rpm:"prrte-libs-debuginfo~2.0.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openmpi", rpm:"python3-openmpi~4.1.5~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm", rpm:"slurm~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-contribs", rpm:"slurm-contribs~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debuginfo", rpm:"slurm-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debugsource", rpm:"slurm-debugsource~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-devel", rpm:"slurm-devel~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-doc", rpm:"slurm-doc~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-gui", rpm:"slurm-gui~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-gui-debuginfo", rpm:"slurm-gui-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-libs", rpm:"slurm-libs~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-libs-debuginfo", rpm:"slurm-libs-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-nss_slurm", rpm:"slurm-nss_slurm~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-nss_slurm-debuginfo", rpm:"slurm-nss_slurm-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-openlava", rpm:"slurm-openlava~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm", rpm:"slurm-pam_slurm~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm-debuginfo", rpm:"slurm-pam_slurm-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-perlapi", rpm:"slurm-perlapi~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-perlapi-debuginfo", rpm:"slurm-perlapi-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-rrdtool", rpm:"slurm-rrdtool~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-rrdtool-debuginfo", rpm:"slurm-rrdtool-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmctld", rpm:"slurm-slurmctld~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmctld-debuginfo", rpm:"slurm-slurmctld-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmd", rpm:"slurm-slurmd~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmd-debuginfo", rpm:"slurm-slurmd-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd", rpm:"slurm-slurmdbd~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd-debuginfo", rpm:"slurm-slurmdbd-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmrestd", rpm:"slurm-slurmrestd~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmrestd-debuginfo", rpm:"slurm-slurmrestd-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque", rpm:"slurm-torque~22.05.9~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque-debuginfo", rpm:"slurm-torque-debuginfo~22.05.9~5.fc39", rls:"FC39"))) {
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
