# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.98718210065987");
  script_cve_id("CVE-2006-10002", "CVE-2006-10003");
  script_tag(name:"creation_date", value:"2026-03-30 04:59:52 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-19 18:16:12 +0000 (Thu, 19 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-b7182d65b7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-b7182d65b7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-b7182d65b7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448965");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449269");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449278");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-XML-Parser' package(s) announced via the FEDORA-2026-b7182d65b7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"2.51 bump - Fix CVE-2006-10002, CVE-2006-10003");

  script_tag(name:"affected", value:"'perl-XML-Parser' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-Parser", rpm:"perl-XML-Parser~2.51~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-Parser-debuginfo", rpm:"perl-XML-Parser-debuginfo~2.51~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-Parser-debugsource", rpm:"perl-XML-Parser-debugsource~2.51~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-Parser-tests", rpm:"perl-XML-Parser-tests~2.51~1.fc43", rls:"FC43"))) {
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
