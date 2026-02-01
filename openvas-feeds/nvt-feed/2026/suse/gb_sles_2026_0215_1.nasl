# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0215.1");
  script_cve_id("CVE-2025-68973");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 14:45:55 +0000 (Wed, 07 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0215-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0215-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260215-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256390");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023870.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpg2' package(s) announced via the SUSE-SU-2026:0215-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gpg2 fixes the following issues:

- CVE-2025-68973: Fix possible memory corruption in the armor parser (gpg.fail/memcpy)(bsc#1255715).
- Avoid potential downgrade to SHA1 in 3rd party key signatures (gpg.fail/sha1) (bsc#1256246).
- Error out on unverified output for non-detached signatures (gpg.fail/detached) (bsc#1256244).
- Fix a memory leak in gpg2 agent (bsc#1256243).
- Fix Cleartext Signature Forgery in the NotDashEscaped header implementation in GnuPG (gpg.fail/notdash) (bsc#1256390).");

  script_tag(name:"affected", value:"'gpg2' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dirmngr", rpm:"dirmngr~2.4.4~150600.3.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpg2", rpm:"gpg2~2.4.4~150600.3.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpg2-lang", rpm:"gpg2-lang~2.4.4~150600.3.12.1", rls:"SLES15.0SP6"))) {
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
