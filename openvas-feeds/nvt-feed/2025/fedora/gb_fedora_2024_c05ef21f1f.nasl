# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9905101102211021102");
  script_cve_id("CVE-2024-10224");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 17:36:44 +0000 (Tue, 26 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c05ef21f1f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c05ef21f1f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c05ef21f1f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327530");
  script_xref(name:"URL", value:"https://github.com/rschupp/PAR-Packer/issues/88");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Module-ScanDeps' package(s) announced via the FEDORA-2024-c05ef21f1f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"1.37
- fix parsing of 'use if ...'
 Fixes errors in PAR::Packer test t/90-rt59710.t
- add test for _parse_libs()
1.36
- Fix CVE-2024-10224: Unsanitized input leads to LPE
 - use three-argument open()
 - replace 'eval '...'' constructs
 Note: this version was not released on CPAN because of
 Coordinated Release Date for CVE
- README: add 'Source Repository' and 'Contact' info
 switch 'Please submit bug reports to ...' to GitHub issues
- add preload rule for MooX::HandlesVia
 cf. [link moved to references]");

  script_tag(name:"affected", value:"'perl-Module-ScanDeps' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-ScanDeps", rpm:"perl-Module-ScanDeps~1.37~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-ScanDeps-tests", rpm:"perl-Module-ScanDeps-tests~1.37~1.fc41", rls:"FC41"))) {
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
