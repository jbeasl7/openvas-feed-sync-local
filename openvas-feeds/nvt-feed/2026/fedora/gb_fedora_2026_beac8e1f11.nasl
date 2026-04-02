# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9810197998101110211");
  script_cve_id("CVE-2026-3836");
  script_tag(name:"creation_date", value:"2026-03-13 04:36:55 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-13T15:49:08+0000");
  script_tag(name:"last_modification", value:"2026-03-13 15:49:08 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-beac8e1f11)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-beac8e1f11");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-beac8e1f11");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445770");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445771");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnf5' package(s) announced via the FEDORA-2026-beac8e1f11 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release fixes CVE-2026-3836 (a crash in dnf5daemon-server when receiving an unknown locale from a D-Bus client.");

  script_tag(name:"affected", value:"'dnf5' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnf5", rpm:"dnf5~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-debuginfo", rpm:"dnf5-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-debugsource", rpm:"dnf5-debugsource~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-devel", rpm:"dnf5-devel~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-plugin-automatic", rpm:"dnf5-plugin-automatic~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-plugin-automatic-debuginfo", rpm:"dnf5-plugin-automatic-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-plugins", rpm:"dnf5-plugins~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5-plugins-debuginfo", rpm:"dnf5-plugins-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5daemon-client", rpm:"dnf5daemon-client~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5daemon-client-debuginfo", rpm:"dnf5daemon-client-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5daemon-server", rpm:"dnf5daemon-server~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5daemon-server-debuginfo", rpm:"dnf5daemon-server-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnf5daemon-server-polkit", rpm:"dnf5daemon-server-polkit~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5", rpm:"libdnf5~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-cli", rpm:"libdnf5-cli~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-cli-debuginfo", rpm:"libdnf5-cli-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-cli-devel", rpm:"libdnf5-cli-devel~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-debuginfo", rpm:"libdnf5-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-devel", rpm:"libdnf5-devel~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-actions", rpm:"libdnf5-plugin-actions~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-actions-debuginfo", rpm:"libdnf5-plugin-actions-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-appstream", rpm:"libdnf5-plugin-appstream~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-appstream-debuginfo", rpm:"libdnf5-plugin-appstream-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-expired-pgp-keys", rpm:"libdnf5-plugin-expired-pgp-keys~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-expired-pgp-keys-debuginfo", rpm:"libdnf5-plugin-expired-pgp-keys-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-local", rpm:"libdnf5-plugin-local~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-local-debuginfo", rpm:"libdnf5-plugin-local-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-rhsm", rpm:"libdnf5-plugin-rhsm~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf5-plugin-rhsm-debuginfo", rpm:"libdnf5-plugin-rhsm-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libdnf5", rpm:"perl-libdnf5~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libdnf5-cli", rpm:"perl-libdnf5-cli~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libdnf5-cli-debuginfo", rpm:"perl-libdnf5-cli-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libdnf5-debuginfo", rpm:"perl-libdnf5-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5", rpm:"python3-libdnf5~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5-cli", rpm:"python3-libdnf5-cli~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5-cli-debuginfo", rpm:"python3-libdnf5-cli-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5-debuginfo", rpm:"python3-libdnf5-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5-python-plugins-loader", rpm:"python3-libdnf5-python-plugins-loader~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf5-python-plugins-loader-debuginfo", rpm:"python3-libdnf5-python-plugins-loader-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libdnf5", rpm:"ruby-libdnf5~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libdnf5-cli", rpm:"ruby-libdnf5-cli~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libdnf5-cli-debuginfo", rpm:"ruby-libdnf5-cli-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libdnf5-debuginfo", rpm:"ruby-libdnf5-debuginfo~5.2.18.0~2.fc42", rls:"FC42"))) {
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
