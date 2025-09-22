# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.49997100989779729");
  script_cve_id("CVE-2024-52805", "CVE-2024-52815", "CVE-2024-53863", "CVE-2024-53867");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 14:59:05 +0000 (Tue, 26 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-4cadba7a29)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4cadba7a29");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4cadba7a29");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330235");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330236");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330238");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330240");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse' package(s) announced via the FEDORA-2024-4cadba7a29 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-52805, CVE-2024-52815, CVE-2024-53863, CVE-2024-53867

----

Backport fixes from v1.120.1");

  script_tag(name:"affected", value:"'matrix-synapse' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+cache_memory", rpm:"matrix-synapse+cache_memory~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+jwt", rpm:"matrix-synapse+jwt~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+matrix-synapse-ldap3", rpm:"matrix-synapse+matrix-synapse-ldap3~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+oidc", rpm:"matrix-synapse+oidc~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+postgres", rpm:"matrix-synapse+postgres~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+saml2", rpm:"matrix-synapse+saml2~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+sentry", rpm:"matrix-synapse+sentry~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+systemd", rpm:"matrix-synapse+systemd~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+url_preview", rpm:"matrix-synapse+url_preview~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+user-search", rpm:"matrix-synapse+user-search~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debuginfo", rpm:"matrix-synapse-debuginfo~1.118.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debugsource", rpm:"matrix-synapse-debugsource~1.118.0~3.fc41", rls:"FC41"))) {
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
