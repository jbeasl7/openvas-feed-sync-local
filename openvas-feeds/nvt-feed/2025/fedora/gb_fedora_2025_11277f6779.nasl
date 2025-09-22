# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.112771026779");
  script_cve_id("CVE-2024-47848");
  script_tag(name:"creation_date", value:"2025-01-27 04:08:22 +0000 (Mon, 27 Jan 2025)");
  script_version("2025-01-27T05:37:51+0000");
  script_tag(name:"last_modification", value:"2025-01-27 05:37:51 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-11277f6779)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-11277f6779");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-11277f6779");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316896");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338424");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/5NYC4UZLY3MWQZ6DYJAUQRJG2ZHZFBJ6/");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/wikitech-l@lists.wikimedia.org/thread/PFTE5RHUERS6KTUGGRZO7XXV5THNJ77E/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the FEDORA-2025-11277f6779 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[links moved to references]");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.41.5~1.fc40", rls:"FC40"))) {
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
