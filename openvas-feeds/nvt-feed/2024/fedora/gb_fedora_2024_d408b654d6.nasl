# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886786");
  script_cve_id("CVE-2024-31208");
  script_tag(name:"creation_date", value:"2024-05-27 10:40:54 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-d408b654d6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d408b654d6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d408b654d6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse, rust-pythonize' package(s) announced via the FEDORA-2024-d408b654d6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update matrix-synapse to v1.105.1 (CVE-2024-31208)

----

Update to v1.105.0");

  script_tag(name:"affected", value:"'matrix-synapse, rust-pythonize' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+cache_memory", rpm:"matrix-synapse+cache_memory~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+jwt", rpm:"matrix-synapse+jwt~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+matrix-synapse-ldap3", rpm:"matrix-synapse+matrix-synapse-ldap3~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+oidc", rpm:"matrix-synapse+oidc~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+postgres", rpm:"matrix-synapse+postgres~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+saml2", rpm:"matrix-synapse+saml2~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+sentry", rpm:"matrix-synapse+sentry~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+systemd", rpm:"matrix-synapse+systemd~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+url_preview", rpm:"matrix-synapse+url_preview~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+user-search", rpm:"matrix-synapse+user-search~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debuginfo", rpm:"matrix-synapse-debuginfo~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debugsource", rpm:"matrix-synapse-debugsource~1.105.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pythonize+default-devel", rpm:"rust-pythonize+default-devel~0.21.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pythonize", rpm:"rust-pythonize~0.21.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pythonize-devel", rpm:"rust-pythonize-devel~0.21.1~1.fc39", rls:"FC39"))) {
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
