# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0267.1");
  script_cve_id("CVE-2024-11218", "CVE-2024-1753", "CVE-2024-9341", "CVE-2024-9407", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"creation_date", value:"2025-01-29 04:23:37 +0000 (Wed, 29 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0267-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0267-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250267-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236270");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020225.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2025:0267-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

- CVE-2024-9676: github.com/containers/storage: Fixed symlink traversal vulnerability in the containers/storage library can cause Denial of Service (DoS) (bsc#1231698)

- Load ip_tables and ip6_tables kernel module (bsc#1214612)
 * Required for rootless mode as a regular user has no permission
 to load kernel modules

- CVE-2024-9675: Fixed cache arbitrary directory mount in buildah (bsc#1231499)
- CVE-2024-9407: Fixed Improper Input Validation in bind-propagation Option of Dockerfile RUN --mount Instruction in buildah (bsc#1231208)
- CVE-2024-9341: cri-o: FIPS Crypto-Policy Directory Mounting Issue in containers/common Go Library (bsc#1231230)
- CVE-2024-1753: Fixed full container escape at build time in buildah (bsc#1221677)
- CVE-2024-11218: Fixed a container breakout by using --jobs=2 and a race condition when building a malicious Containerfile. (bsc#1236270)

- Refactor network backend dependencies:
 * podman requires either netavark or cni-plugins. On ALP, require
 netavark, otherwise prefer netavark but don't force it.
 * This fixes missing cni-plugins in some scenarios
 * Default to netavark everywhere where it's available");

  script_tag(name:"affected", value:"'podman' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150400.4.35.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.5~150400.4.35.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.5~150400.4.35.1", rls:"SLES15.0SP4"))) {
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
