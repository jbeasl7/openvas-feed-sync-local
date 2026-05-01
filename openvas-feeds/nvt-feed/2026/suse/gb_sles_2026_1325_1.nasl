# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1325.1");
  script_cve_id("CVE-2026-20031");
  script_tag(name:"creation_date", value:"2026-04-16 05:02:43 +0000 (Thu, 16 Apr 2026)");
  script_version("2026-04-16T06:18:46+0000");
  script_tag(name:"last_modification", value:"2026-04-16 06:18:46 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-04 18:16:16 +0000 (Wed, 04 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1325-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261325-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2026:1325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

Update to clamav 1.5.2:

Security issue:

- CVE-2026-20031: improper error handling in the HTML CSS module when splitting UTF-8 strings can lead to denial of
 service conditions via a crafted HTML file (bsc#1259207).

Non security issue:

- Support transactional updates (jsc#PED-14819).

Changelog:

 * Fixed a possible infinite loop when scanning some JPEG files by
 upgrading affected ClamAV dependency, a Rust image library.
 * The CVD verification process will now ignore certificate files
 in the CVD certs directory when the user lacks read permissions.
 * Freshclam: Fix CLD verification bug with PrivateMirror option.
 * Upgraded the Rust bytes dependency to a newer version to
 resolve RUSTSEC-2026-0007 advisory.
 * Fixed a possible crash caused by invalid pointer alignment on
 some platforms.
 * Minimal required Rust version is now 1.87.");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-docs-html", rpm:"clamav-docs-html~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav12", rpm:"libclamav12~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam4", rpm:"libfreshclam4~1.5.2~150600.18.25.1", rls:"SLES15.0SP6"))) {
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
