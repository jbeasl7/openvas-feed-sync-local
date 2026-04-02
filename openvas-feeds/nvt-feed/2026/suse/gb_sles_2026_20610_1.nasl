# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20610.1");
  script_cve_id("CVE-2024-45310", "CVE-2025-22872", "CVE-2025-64324", "CVE-2025-64432", "CVE-2025-64433", "CVE-2025-64434", "CVE-2025-64435", "CVE-2025-64437");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-25 17:16:59 +0000 (Tue, 25 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20610-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20610-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620610-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257422");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024607.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubevirt' package(s) announced via the SUSE-SU-2026:20610-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubevirt fixes the following issues:

Update to version 1.7.0 (bsc#1257128).

Security issues fixed:

 - CVE-2025-64435: logic flaw in the virt-controller can lead to incorrect status updates and potentially causing a DoS
 (bsc#1253189).
 - CVE-2024-45310: kubevirt vendored github.com/opencontainers/runc/libcontainer/utils: runc can be tricked into
 creating empty files/directories on host (bsc#1257422).
 - CVE-2025-22872: incorrectly interpreted tags can cause content to be placed wrong scope during DOM construction
 (bsc#1241772).
 - CVE-2025-64432: fail to correctly validate certain fields in the client TLS certificate may allow an attacker to
 bypass existing RBAC controls (bsc#1253181).
 - CVE-2025-64433: improper symlink handling can allow to read arbitrary files (bsc#1253185).
 - CVE-2025-64434: compromising virt-handler instance can lead to impersonate virt-api and execute privileged operations
 (bsc#1253186).
 - CVE-2025-64437: mishandling of symlinks can lead to compromising the CIA (bsc#1253194).
 - CVE-2025-64324: a logic bug that allows an attacker to read and write arbitrary files owned by more privileged users
 (bsc#1253748).

Other updates and bugfixes:

 - Upstream now uses stateless firmware for CoCo VMs.");

  script_tag(name:"affected", value:"'kubevirt' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl", rpm:"kubevirt-virtctl~1.7.0~160000.1.1", rls:"SLES16.0.0"))) {
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
