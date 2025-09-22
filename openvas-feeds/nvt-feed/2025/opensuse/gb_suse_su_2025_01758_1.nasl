# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01758.1");
  script_cve_id("CVE-2025-43904");
  script_tag(name:"creation_date", value:"2025-06-02 04:12:38 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01758-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01758-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501758-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243666");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039402.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_23_02' package(s) announced via the SUSE-SU-2025:01758-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_23_02 fixes the following issues:

- CVE-2025-43904: an issue with permission handling for Coordinators within the accounting system allowed Coordinators
 to promote a user to Administrator (bsc#1243666).");

  script_tag(name:"affected", value:"'slurm_23_02' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_23_02", rpm:"libnss_slurm2_23_02~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_23_02", rpm:"libpmi0_23_02~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_23_02", rpm:"perl-slurm_23_02~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02", rpm:"slurm_23_02~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-auth-none", rpm:"slurm_23_02-auth-none~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config", rpm:"slurm_23_02-config~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config-man", rpm:"slurm_23_02-config-man~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-cray", rpm:"slurm_23_02-cray~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-devel", rpm:"slurm_23_02-devel~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-doc", rpm:"slurm_23_02-doc~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-hdf5", rpm:"slurm_23_02-hdf5~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-lua", rpm:"slurm_23_02-lua~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-munge", rpm:"slurm_23_02-munge~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-node", rpm:"slurm_23_02-node~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-openlava", rpm:"slurm_23_02-openlava~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-pam_slurm", rpm:"slurm_23_02-pam_slurm~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugin-ext-sensors-rrd", rpm:"slurm_23_02-plugin-ext-sensors-rrd~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugins", rpm:"slurm_23_02-plugins~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-rest", rpm:"slurm_23_02-rest~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-seff", rpm:"slurm_23_02-seff~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sjstat", rpm:"slurm_23_02-sjstat~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-slurmdbd", rpm:"slurm_23_02-slurmdbd~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sql", rpm:"slurm_23_02-sql~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sview", rpm:"slurm_23_02-sview~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-testsuite", rpm:"slurm_23_02-testsuite~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-torque", rpm:"slurm_23_02-torque~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-webdoc", rpm:"slurm_23_02-webdoc~23.02.7~150300.7.20.1", rls:"openSUSELeap15.6"))) {
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
