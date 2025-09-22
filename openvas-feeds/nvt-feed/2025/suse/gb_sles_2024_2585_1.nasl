# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2585.1");
  script_cve_id("CVE-2024-0090", "CVE-2024-0091", "CVE-2024-0092");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-15 22:20:16 +0000 (Thu, 15 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2585-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242585-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227575");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036081.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware-nvidia-gspx-G06' package(s) announced via the SUSE-SU-2024:2585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06 fixes the following issues:

Update to version 555.42.06 for CUDA.

Security Update 550.90.07:

- CVE-2024-0090: Fixed out of bounds write (bsc#1223356).
- CVE-2024-0092: Fixed incorrect exception handling (bsc#1223356).
- CVE-2024-0091: Fixed untrusted pointer dereference (bsc#1223356).

Changes in kernel-firmware-nvidia-gspx-G06:

- Update to 550.100 (bsc#1227575)

- Add a second flavor to be used by the kernel module versions
 used by CUDA. The firmware targetting CUDA contains '-cuda' in
 its name to track its versions separately from the graphics
 firmware. (bsc#1227417)

Changes in nvidia-open-driver-G06-signed:

- Update to 550.100 (bsc#1227575)

 * Fixed a bug that caused OpenGL triple buffering to behave like
 double buffering.

- To avoid issues with missing dependencies when no CUDA repo
 is present make the dependecy to nvidia-compute-G06 conditional.

- CUDA is not available for Tumbleweed, exclude the build of the
 cuda flavor.

- preamble: let the -cuda flavor KMP require the -cuda flavor
 firmware

- Add a second flavor for building the kernel module versions
 used by CUDA. The kmp targetting CUDA contains '-cuda' in
 its name to track its versions separately from the graphics
 kmp. (bsc#1227417)
- Provide the meta package nv-prefer-signed-open-driver to
 make sure the latest available SUSE-build open driver is
 installed - independent of the latest available open driver
 version in he CUDA repository.
 Rationale:
 The package cuda-runtime provides the link between CUDA and
 the kernel driver version through a
 Requires: cuda-drivers >= %version
 This implies that a CUDA version will run withany kernel driver
 version equal or higher than a base version.
 nvidia-compute-G06 provides the glue layer between CUDA and
 a specific version of he kernel driver both by providing
 a set of base libraries and by requiring a specific kernel
 version. 'cuda-drivers' (provided by nvidia-compute-utils-G06)
 requires an unversioned nvidia-compute-G06. With this, the
 resolver will install the latest available and applicable
 nvidia-compute-G06.
 nv-prefer-signed-open-driver then represents the latest available
 open driver version and restricts the nvidia-compute-G06 version
 to it. (bsc#1227419)");

  script_tag(name:"affected", value:"'kernel-firmware-nvidia-gspx-G06' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~550.100~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06-cuda", rpm:"kernel-firmware-nvidia-gspx-G06-cuda~555.42.06~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~555.42.06~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.100~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~555.42.06~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~555.42.06~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~555.42.06_k6.4.0_150600.23.7~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~555.42.06_k6.4.0_150600.23.7~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.100~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.100_k6.4.0_150600.23.7~150600.3.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.100_k6.4.0_150600.23.7~150600.3.7.1", rls:"SLES15.0SP6"))) {
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
