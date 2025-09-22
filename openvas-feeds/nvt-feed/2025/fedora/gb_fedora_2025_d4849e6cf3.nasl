# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10048491016991023");
  script_cve_id("CVE-2025-32873", "CVE-2025-48432");
  script_tag(name:"creation_date", value:"2025-06-17 04:10:20 +0000 (Tue, 17 Jun 2025)");
  script_version("2025-06-18T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-06-18 05:40:25 +0000 (Wed, 18 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 19:44:20 +0000 (Tue, 17 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-d4849e6cf3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d4849e6cf3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d4849e6cf3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2365045");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django4.2' package(s) announced via the FEDORA-2025-d4849e6cf3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Fixes CVE-2025-32873: Denial-of-service possibility in strip_tags()
 - Fixes CVE-2025-48432: Potential log injection via unescaped request path");

  script_tag(name:"affected", value:"'python-django4.2' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django4.2", rpm:"python-django4.2~4.2.22~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django4.2-bash-completion", rpm:"python-django4.2-bash-completion~4.2.22~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django4.2", rpm:"python3-django4.2~4.2.22~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django4.2-doc", rpm:"python3-django4.2-doc~4.2.22~1.fc41", rls:"FC41"))) {
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
