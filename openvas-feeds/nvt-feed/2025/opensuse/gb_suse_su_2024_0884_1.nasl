# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0884.1");
  script_cve_id("CVE-2023-20593");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:20 +0000 (Tue, 01 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0884-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240884-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018179.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spectre-meltdown-checker' package(s) announced via the SUSE-SU-2024:0884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spectre-meltdown-checker fixes the following issues:

- updated to 0.46
 This release mainly focuses on the detection of the new Zenbleed
 (CVE-2023-20593) vulnerability, among few other changes that were in
 line waiting for a release:
 - feat: detect the vulnerability and mitigation of Zenbleed (CVE-2023-20593)
 - feat: add the linux-firmware repository as another source for CPU microcode versions
 - feat: arm: add Neoverse-N2, Neoverse-V1 and Neoverse-V2
 - fix: docker: adding missing utils (#433)
 - feat: add support for Guix System kernel
 - fix: rewrite SQL to be sqlite3 >= 3.41 compatible (#443)
 - fix: a /devnull file was mistakenly created on the filesystem
 - fix: fwdb: ignore MCEdb versions where an official Intel version exists (fixes #430)

- updated to 0.45
 - arm64: phytium: Add CPU Implementer Phytium
 - arm64: variant 4: detect ssbd mitigation from kernel img, system.map or kconfig
 - chore: ensure vars are set before being dereferenced (set -u compat)
 - chore: fix indentation
 - chore: fwdb: update to v220+i20220208
 - chore: only attempt to load msr and cpuid module once
 - chore: read_cpuid: use named constants
 - chore: readme: framapic is gone, host the screenshots on GitHub
 - chore: replace 'Vulnerable to' by 'Affected by' in the hw section
 - chore: speculative execution -> transient execution
 - chore: update fwdb to v222+i20220208
 - chore: update Intel Family 6 models
 - chore: wording: model not vulnerable -> model not affected
 - doc: add an FAQ entry about CVE support
 - doc: add an FAQ.md and update the README.md accordingly
 - doc: more FAQ and README
 - doc: readme: make the FAQ entry more visible
 - feat: add --allow-msr-write, no longer write by default (#385), detect when writing is denied
 - feat: add --cpu, apply changes to (read<pipe>write)_msr, update fwdb to v221+i20220208
 - feat: add subleaf != 0 support for read_cpuid
 - feat: arm: add Cortex A77 and Neoverse-N1 (fixes #371)
 - feat: bsd: for unimplemented CVEs, at least report when CPU is not affected
 - feat: hw check: add IPRED, RRSBA, BHI features check
 - feat: implement detection for MCEPSC under BSD
 - feat: set default TMPDIR for Android (#415)
 - fix: extract_kernel: don't overwrite kernel_err if already set
 - fix: has_vmm false positive with pcp
 - fix: is_ucode_blacklisted: fix some model names
 - fix: mcedb: v191 changed the MCE table format
 - fix: refuse to run under MacOS and ESXi
 - fix: retpoline: detection on 5.15.28+ (#420)
 - fix: variant4: added case where prctl ssbd status is tagged as 'unknown'");

  script_tag(name:"affected", value:"'spectre-meltdown-checker' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"spectre-meltdown-checker", rpm:"spectre-meltdown-checker~0.46~150100.3.9.1", rls:"openSUSELeap15.5"))) {
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
