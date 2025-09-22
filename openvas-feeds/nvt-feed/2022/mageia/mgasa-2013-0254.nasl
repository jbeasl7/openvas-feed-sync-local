# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0254");
  script_cve_id("CVE-2011-4363");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0254)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0254");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0254.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10928");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113068.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Proc-ProcessTable' package(s) announced via the MGASA-2013-0254 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated perl-Proc-ProcessTable package fixes security vulnerability:

ProcessTable.pm in the Proc::ProcessTable module 0.45 for Perl, when TTY
information caching is enabled, allows local users to overwrite arbitrary
files via a symlink attack on /tmp/TTYDEVS (CVE-2011-4363).");

  script_tag(name:"affected", value:"'perl-Proc-ProcessTable' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Proc-ProcessTable", rpm:"perl-Proc-ProcessTable~0.480.0~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Proc-ProcessTable", rpm:"perl-Proc-ProcessTable~0.480.0~1.mga3", rls:"MAGEIA3"))) {
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
