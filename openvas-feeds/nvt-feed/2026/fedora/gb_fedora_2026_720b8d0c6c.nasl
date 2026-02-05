# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.720988100099699");
  script_cve_id("CVE-2026-24486");
  script_tag(name:"creation_date", value:"2026-02-04 04:35:12 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-04T05:55:03+0000");
  script_tag(name:"last_modification", value:"2026-02-04 05:55:03 +0000 (Wed, 04 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-720b8d0c6c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-720b8d0c6c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-720b8d0c6c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2432631");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433374");
  script_xref(name:"URL", value:"https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-24486");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-python-multipart' package(s) announced via the FEDORA-2026-720b8d0c6c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for [CVE-2026-24486]([link moved to references]) / [GHSA-wp53-j4wj-2cfg]([link moved to references]).

----

## 0.0.22 (2026-01-25)

* Drop directory path from filename in `File`");

  script_tag(name:"affected", value:"'python-python-multipart' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-python-multipart", rpm:"python-python-multipart~0.0.22~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-python-multipart", rpm:"python3-python-multipart~0.0.22~1.fc42", rls:"FC42"))) {
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
