# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.1002124788978");
  script_cve_id("CVE-2024-11003", "CVE-2024-48990", "CVE-2024-48991", "CVE-2024-48992");
  script_tag(name:"creation_date", value:"2024-11-25 08:44:53 +0000 (Mon, 25 Nov 2024)");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-d2124788a8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d2124788a8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d2124788a8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327534");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327540");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327545");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327552");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'needrestart' package(s) announced via the FEDORA-2024-d2124788a8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebase to fix CVEs");

  script_tag(name:"affected", value:"'needrestart' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"needrestart", rpm:"needrestart~3.8~1.fc40", rls:"FC40"))) {
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
