# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3100102102292265");
  script_cve_id("CVE-2024-55224", "CVE-2024-55225", "CVE-2024-55226", "CVE-2024-56335");
  script_tag(name:"creation_date", value:"2025-01-29 11:41:55 +0000 (Wed, 29 Jan 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-19 13:46:58 +0000 (Tue, 19 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3dff292265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3dff292265");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3dff292265");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307705");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333596");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336826");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336827");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336829");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336830");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336831");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336833");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336834");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336835");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vaultwarden' package(s) announced via the FEDORA-2025-3dff292265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fix VW_VERSION in compiled code, patch security issues");

  script_tag(name:"affected", value:"'vaultwarden' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"vaultwarden", rpm:"vaultwarden~1.32.7~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vaultwarden-debuginfo", rpm:"vaultwarden-debuginfo~1.32.7~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vaultwarden-debugsource", rpm:"vaultwarden-debugsource~1.32.7~4.fc40", rls:"FC40"))) {
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
