# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884796");
  script_cve_id("CVE-2023-41053");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:24 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 12:00:51 +0000 (Tue, 12 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-5a7cc198c2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5a7cc198c2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5a7cc198c2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237826");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238560");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the FEDORA-2023-5a7cc198c2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Redis 7.2.1** Released Wed 06 Sep 2023 15:00:00 IDT

Upgrade urgency SECURITY: See security fixes below.

Security Fixes

* (**CVE-2023-41053**) Redis does not correctly identify keys accessed by SORT_RO and,
 as a result, may grant users executing this command access to keys that are not
 explicitly authorized by the ACL configuration.

Bug Fixes

* Fix crashes when joining a node to an existing 7.0 Redis Cluster (#12538)
* Correct request_policy and response_policy command tips on for some admin /
 configuration commands (#12545, #12530)");

  script_tag(name:"affected", value:"'redis' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~7.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~7.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-devel", rpm:"redis-devel~7.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-doc", rpm:"redis-doc~7.2.1~1.fc39", rls:"FC39"))) {
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
