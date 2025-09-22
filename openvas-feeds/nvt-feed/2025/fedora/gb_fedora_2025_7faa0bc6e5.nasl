# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.710297970989961015");
  script_cve_id("CVE-2025-47947");
  script_tag(name:"creation_date", value:"2025-06-09 04:11:16 +0000 (Mon, 09 Jun 2025)");
  script_version("2025-06-10T05:40:17+0000");
  script_tag(name:"last_modification", value:"2025-06-10 05:40:17 +0000 (Tue, 10 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-7faa0bc6e5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-7faa0bc6e5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-7faa0bc6e5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367908");
  script_xref(name:"URL", value:"https://github.com/owasp-modsecurity/ModSecurity/releases/tag/v2.9.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_security' package(s) announced via the FEDORA-2025-7faa0bc6e5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update includes `mod_security` version **2.9.9** which addresses `CVE-2025-47947` and includes various bug fixes. See [link moved to references] for more information on the changes in this release.");

  script_tag(name:"affected", value:"'mod_security' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mod_security", rpm:"mod_security~2.9.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_security-debuginfo", rpm:"mod_security-debuginfo~2.9.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_security-debugsource", rpm:"mod_security-debugsource~2.9.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_security-mlogc", rpm:"mod_security-mlogc~2.9.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_security-mlogc-debuginfo", rpm:"mod_security-mlogc-debuginfo~2.9.9~1.fc42", rls:"FC42"))) {
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
