# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885169");
  script_cve_id("CVE-2023-30534", "CVE-2023-31132", "CVE-2023-39357", "CVE-2023-39358", "CVE-2023-39359", "CVE-2023-39360", "CVE-2023-39361", "CVE-2023-39362", "CVE-2023-39364", "CVE-2023-39365", "CVE-2023-39366", "CVE-2023-39510", "CVE-2023-39511", "CVE-2023-39512", "CVE-2023-39513", "CVE-2023-39514", "CVE-2023-39515", "CVE-2023-39516");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:56 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-08 17:42:39 +0000 (Fri, 08 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-248dff7cbe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-248dff7cbe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-248dff7cbe");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237577");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237582");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237585");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237588");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237592");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237600");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237603");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237606");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237609");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237611");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237615");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237618");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237621");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237624");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237627");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237819");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/releases/tag/release%2F1.2.25");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, cacti-spine' package(s) announced via the FEDORA-2023-248dff7cbe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update cacti and cacti-spine to version 1.2.25. This includes the upstream fixes for many CVEs.

[link moved to references]");

  script_tag(name:"affected", value:"'cacti, cacti-spine' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.25~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.25~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.2.25~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.2.25~1.fc39", rls:"FC39"))) {
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
