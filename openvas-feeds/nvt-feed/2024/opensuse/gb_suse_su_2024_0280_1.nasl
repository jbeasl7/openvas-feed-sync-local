# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833795");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-49933", "CVE-2023-49935", "CVE-2023-49936", "CVE-2023-49937", "CVE-2023-49938");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:17:34 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:53:51 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for slurm_23_02 (SUSE-SU-2024:0280-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0280-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YWNFXE6YS5VJYKCXOJ7KKCC4XFQOHCYJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_23_02'
  package(s) announced via the SUSE-SU-2024:0280-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_23_02 fixes the following issues:

  Update to slurm 23.02.6:

  Security fixes:

  * CVE-2023-49933: Prevent message extension attacks that could bypass the
      message hash. (bsc#1218046)

  * CVE-2023-49935: Prevent message hash bypass in slurmd which can allow an
      attacker to reuse root-level MUNGE tokens and escalate permissions.
      (bsc#1218049)

  * CVE-2023-49936: Prevent NULL pointer dereference on `size_valp` overflow.
      (bsc#1218050)

  * CVE-2023-49937: Prevent double-xfree() on error in
      `_unpack_node_reg_resp()`. (bsc#1218051)

  * CVE-2023-49938: Prevent modified `sbcast` RPCs from opening a file with the
      wrong group permissions. (bsc#1218053)

  Other fixes:

  * Add missing service file for slurmrestd (bsc#1217711).

  * Fix slurm upgrading to incompatible versions (bsc#1216869).

  ##");

  script_tag(name:"affected", value:"'slurm_23_02' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-slurmdbd-debuginfo", rpm:"slurm_23_02-slurmdbd-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugins", rpm:"slurm_23_02-plugins~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-hdf5", rpm:"slurm_23_02-hdf5~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-torque", rpm:"slurm_23_02-torque~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_23_02", rpm:"libnss_slurm2_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sview", rpm:"slurm_23_02-sview~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-debuginfo", rpm:"slurm_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-auth-none", rpm:"slurm_23_02-auth-none~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02", rpm:"slurm_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-rest", rpm:"slurm_23_02-rest~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugin-ext-sensors-rrd", rpm:"slurm_23_02-plugin-ext-sensors-rrd~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-pam_slurm-debuginfo", rpm:"slurm_23_02-pam_slurm-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-lua", rpm:"slurm_23_02-lua~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_23_02", rpm:"perl-slurm_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-munge-debuginfo", rpm:"slurm_23_02-munge-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm39-debuginfo", rpm:"libslurm39-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-hdf5-debuginfo", rpm:"slurm_23_02-hdf5-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugin-ext-sensors-rrd-debuginfo", rpm:"slurm_23_02-plugin-ext-sensors-rrd-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-debugsource", rpm:"slurm_23_02-debugsource~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sview-debuginfo", rpm:"slurm_23_02-sview-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-devel", rpm:"slurm_23_02-devel~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-pam_slurm", rpm:"slurm_23_02-pam_slurm~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-rest-debuginfo", rpm:"slurm_23_02-rest-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_23_02-debuginfo", rpm:"perl-slurm_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sql-debuginfo", rpm:"slurm_23_02-sql-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-munge", rpm:"slurm_23_02-munge~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-node", rpm:"slurm_23_02-node~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm39", rpm:"libslurm39~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-cray", rpm:"slurm_23_02-cray~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-node-debuginfo", rpm:"slurm_23_02-node-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-slurmdbd", rpm:"slurm_23_02-slurmdbd~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-testsuite", rpm:"slurm_23_02-testsuite~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-lua-debuginfo", rpm:"slurm_23_02-lua-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_23_02", rpm:"libpmi0_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-torque-debuginfo", rpm:"slurm_23_02-torque-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_23_02-debuginfo", rpm:"libnss_slurm2_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-cray-debuginfo", rpm:"slurm_23_02-cray-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sql", rpm:"slurm_23_02-sql~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-auth-none-debuginfo", rpm:"slurm_23_02-auth-none-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_23_02-debuginfo", rpm:"libpmi0_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugins-debuginfo", rpm:"slurm_23_02-plugins-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config", rpm:"slurm_23_02-config~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-seff", rpm:"slurm_23_02-seff~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sjstat", rpm:"slurm_23_02-sjstat~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-openlava", rpm:"slurm_23_02-openlava~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-webdoc", rpm:"slurm_23_02-webdoc~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config-man", rpm:"slurm_23_02-config-man~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-doc", rpm:"slurm_23_02-doc~23.02.7~150300.7.17.1##", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-slurmdbd-debuginfo", rpm:"slurm_23_02-slurmdbd-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugins", rpm:"slurm_23_02-plugins~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-hdf5", rpm:"slurm_23_02-hdf5~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-torque", rpm:"slurm_23_02-torque~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_23_02", rpm:"libnss_slurm2_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sview", rpm:"slurm_23_02-sview~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-debuginfo", rpm:"slurm_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-auth-none", rpm:"slurm_23_02-auth-none~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02", rpm:"slurm_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-rest", rpm:"slurm_23_02-rest~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugin-ext-sensors-rrd", rpm:"slurm_23_02-plugin-ext-sensors-rrd~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-pam_slurm-debuginfo", rpm:"slurm_23_02-pam_slurm-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-lua", rpm:"slurm_23_02-lua~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_23_02", rpm:"perl-slurm_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-munge-debuginfo", rpm:"slurm_23_02-munge-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm39-debuginfo", rpm:"libslurm39-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-hdf5-debuginfo", rpm:"slurm_23_02-hdf5-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugin-ext-sensors-rrd-debuginfo", rpm:"slurm_23_02-plugin-ext-sensors-rrd-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-debugsource", rpm:"slurm_23_02-debugsource~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sview-debuginfo", rpm:"slurm_23_02-sview-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-devel", rpm:"slurm_23_02-devel~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-pam_slurm", rpm:"slurm_23_02-pam_slurm~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-rest-debuginfo", rpm:"slurm_23_02-rest-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_23_02-debuginfo", rpm:"perl-slurm_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sql-debuginfo", rpm:"slurm_23_02-sql-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-munge", rpm:"slurm_23_02-munge~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-node", rpm:"slurm_23_02-node~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm39", rpm:"libslurm39~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-cray", rpm:"slurm_23_02-cray~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-node-debuginfo", rpm:"slurm_23_02-node-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-slurmdbd", rpm:"slurm_23_02-slurmdbd~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-testsuite", rpm:"slurm_23_02-testsuite~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-lua-debuginfo", rpm:"slurm_23_02-lua-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_23_02", rpm:"libpmi0_23_02~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-torque-debuginfo", rpm:"slurm_23_02-torque-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_23_02-debuginfo", rpm:"libnss_slurm2_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-cray-debuginfo", rpm:"slurm_23_02-cray-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sql", rpm:"slurm_23_02-sql~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-auth-none-debuginfo", rpm:"slurm_23_02-auth-none-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_23_02-debuginfo", rpm:"libpmi0_23_02-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-plugins-debuginfo", rpm:"slurm_23_02-plugins-debuginfo~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config", rpm:"slurm_23_02-config~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-seff", rpm:"slurm_23_02-seff~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-sjstat", rpm:"slurm_23_02-sjstat~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-openlava", rpm:"slurm_23_02-openlava~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-webdoc", rpm:"slurm_23_02-webdoc~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-config-man", rpm:"slurm_23_02-config-man~23.02.7~150300.7.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_23_02-doc", rpm:"slurm_23_02-doc~23.02.7~150300.7.17.1##", rls:"openSUSELeap15.3"))) {
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