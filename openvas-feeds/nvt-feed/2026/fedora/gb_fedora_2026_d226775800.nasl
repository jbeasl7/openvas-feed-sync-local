# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.100226775800");
  script_cve_id("CVE-2026-4177");
  script_tag(name:"creation_date", value:"2026-03-31 04:51:57 +0000 (Tue, 31 Mar 2026)");
  script_version("2026-03-31T06:09:03+0000");
  script_tag(name:"last_modification", value:"2026-03-31 06:09:03 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-d226775800)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-d226775800");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-d226775800");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448281");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-YAML-Syck' package(s) announced via the FEDORA-2026-d226775800 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"`YAML::Syck` versions up to and including 1.36 for Perl has several potential security vulnerabilities including a high-severity heap buffer overflow in the YAML emitter. The heap overflow occurs when class names exceed the initial 512-byte allocation. The base64 decoder could read past the buffer end on trailing newlines. strtok mutated n->type_id in place, corrupting shared node data. A memory leak occurred in syck_hdlr_add_anchor when a node already had an anchor. The incoming anchor string 'a' was leaked on early return.");

  script_tag(name:"affected", value:"'perl-YAML-Syck' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-Syck", rpm:"perl-YAML-Syck~1.39~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-Syck-debuginfo", rpm:"perl-YAML-Syck-debuginfo~1.39~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-Syck-debugsource", rpm:"perl-YAML-Syck-debugsource~1.39~1.fc42", rls:"FC42"))) {
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
