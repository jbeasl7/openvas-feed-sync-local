# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01761.1");
  script_cve_id("CVE-2025-43904");
  script_tag(name:"creation_date", value:"2025-06-02 04:12:38 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01761-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01761-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501761-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243666");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039445.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_24_11' package(s) announced via the SUSE-SU-2025:01761-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_24_11 fixes the following issues:

Update to version 24.11.5.

Security issues fixed:

- CVE-2025-43904: an issue with permission handling for Coordinators within the accounting system allowed Coordinators
 to promote a user to Administrator (bsc#1243666).

Other changes and issues fixed:

- Changes from version 24.11.5

 * Return error to `scontrol` reboot on bad nodelists.
 * `slurmrestd` - Report an error when QOS resolution fails for
 v0.0.40 endpoints.
 * `slurmrestd` - Report an error when QOS resolution fails for
 v0.0.41 endpoints.
 * `slurmrestd` - Report an error when QOS resolution fails for
 v0.0.42 endpoints.
 * `data_parser/v0.0.42` - Added `+inline_enums` flag which
 modifies the output when generating OpenAPI specification.
 It causes enum arrays to not be defined in their own schema
 with references (`$ref`) to them. Instead they will be dumped
 inline.
 * Fix binding error with `tres-bind map/mask` on partial node
 allocations.
 * Fix `stepmgr` enabled steps being able to request features.
 * Reject step creation if requested feature is not available
 in job.
 * `slurmd` - Restrict listening for new incoming RPC requests
 further into startup.
 * `slurmd` - Avoid `auth/slurm` related hangs of CLI commands
 during startup and shutdown.
 * `slurmctld` - Restrict processing new incoming RPC requests
 further into startup. Stop processing requests sooner during
 shutdown.
 * `slurmcltd` - Avoid auth/slurm related hangs of CLI commands
 during startup and shutdown.
 * `slurmctld` - Avoid race condition during shutdown or
 ereconfigure that could result in a crash due delayed
 processing of a connection while plugins are unloaded.
 * Fix small memleak when getting the job list from the database.
 * Fix incorrect printing of `%` escape characters when printing
 stdio fields for jobs.
 * Fix padding parsing when printing stdio fields for jobs.
 * Fix printing `%A` array job id when expanding patterns.
 * Fix reservations causing jobs to be held for `Bad Constraints`.
 * `switch/hpe_slingshot` - Prevent potential segfault on failed
 curl request to the fabric manager.
 * Fix printing incorrect array job id when expanding stdio file
 names. The `%A` will now be substituted by the correct value.
 * Fix printing incorrect array job id when expanding stdio file
 names. The `%A` will now be substituted by the correct value.
 * `switch/hpe_slingshot` - Fix VNI range not updating on slurmctld
 restart or reconfigre.
 * Fix steps not being created when using certain combinations of
 `-c` and `-n` inferior to the jobs requested resources, when
 using stepmgr and nodes are configured with
 `CPUs == Sockets*CoresPerSocket`.
 * Permit configuring the number of retry attempts to destroy CXI
 service via the new destroy_retries `SwitchParameter`.
 * Do not reset `memory.high` and `memory.swap.max` in slurmd
 startup or reconfigure as we are never really ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'slurm_24_11' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_24_11", rpm:"libnss_slurm2_24_11~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_24_11", rpm:"libpmi0_24_11~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm42", rpm:"libslurm42~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_24_11", rpm:"perl-slurm_24_11~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11", rpm:"slurm_24_11~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-auth-none", rpm:"slurm_24_11-auth-none~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-config", rpm:"slurm_24_11-config~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-config-man", rpm:"slurm_24_11-config-man~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-cray", rpm:"slurm_24_11-cray~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-devel", rpm:"slurm_24_11-devel~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-doc", rpm:"slurm_24_11-doc~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-hdf5", rpm:"slurm_24_11-hdf5~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-lua", rpm:"slurm_24_11-lua~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-munge", rpm:"slurm_24_11-munge~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-node", rpm:"slurm_24_11-node~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-openlava", rpm:"slurm_24_11-openlava~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-pam_slurm", rpm:"slurm_24_11-pam_slurm~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-plugins", rpm:"slurm_24_11-plugins~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-rest", rpm:"slurm_24_11-rest~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-seff", rpm:"slurm_24_11-seff~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-sjstat", rpm:"slurm_24_11-sjstat~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-slurmdbd", rpm:"slurm_24_11-slurmdbd~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-sql", rpm:"slurm_24_11-sql~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-sview", rpm:"slurm_24_11-sview~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-testsuite", rpm:"slurm_24_11-testsuite~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-torque", rpm:"slurm_24_11-torque~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_24_11-webdoc", rpm:"slurm_24_11-webdoc~24.11.5~150300.7.8.1", rls:"openSUSELeap15.6"))) {
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
