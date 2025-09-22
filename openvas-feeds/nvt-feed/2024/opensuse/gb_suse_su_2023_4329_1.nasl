# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833268");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-41914");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 22:11:29 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for slurm (SUSE-SU-2023:4329-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4329-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WULQPLOTUZK75YEPOJGDVAGCLQNPBACQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the SUSE-SU-2023:4329-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm fixes the following issues:

  * CVE-2023-41914: Fixed a filesystem handling race conditions that could lead
      to an attacker taking control of an arbitrary file. (bsc#1216207)

  ##");

  script_tag(name:"affected", value:"'slurm' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.13.1", rls:"openSUSELeap15.5"))) {
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