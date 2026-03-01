# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0558.1");
  script_cve_id("CVE-2024-0132", "CVE-2024-0133");
  script_tag(name:"creation_date", value:"2026-02-17 14:14:12 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-02 14:45:36 +0000 (Wed, 02 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0558-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260558-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231033");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024273.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnvidia-container' package(s) announced via the SUSE-SU-2026:0558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libnvidia-container fixes the following issues:

Update to version 1.18.0.

Security issues fixed:

- CVE-2024-0132: time-of-check time-of-use (TOCTOU) race condition in default configuration via specifically
 crafted container image (bsc#1231033).
- CVE-2024-0133: data tampering in host file system via specially crafted container image (bsc#1231032).

Other updates and bugfixes:

- updated to 1.18.0

 - Add clock_gettime to allowed syscalls
 - Fix pointer accessing local variable out of scope
 - Require version match between libnvidia-container-tools and libnvidia-container1
 - Add libnvidia-gpucomp.so to the list of compute libs
 - Use VERSION_ prefix for version parts in makefiles
 - Add additional logging
 - Do not discard container flags when --cuda-compat-mode is not specified
 - Remove unneeded --no-cntlibs argument from list command
 - Add cuda-compat-mode flag to configure command
 - Skip files when user has insufficient permissions
 - Fix building with Go 1.24
 - Add no-cntlibs CLI option to nvidia-container-cli
 - Fix always using fallback
 - Add fallback for systems without memfd_create()
 - Create virtual copy of host ldconfig binary before calling fexecve()
 - Fix some typos in text.

- update nvidia modprobe to expected 550.54.14.
- remove services");

  script_tag(name:"affected", value:"'libnvidia-container' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnvidia-container-devel", rpm:"libnvidia-container-devel~1.18.0~150200.5.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnvidia-container-static", rpm:"libnvidia-container-static~1.18.0~150200.5.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnvidia-container-tools", rpm:"libnvidia-container-tools~1.18.0~150200.5.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnvidia-container1", rpm:"libnvidia-container1~1.18.0~150200.5.9.1", rls:"openSUSELeap15.6"))) {
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
