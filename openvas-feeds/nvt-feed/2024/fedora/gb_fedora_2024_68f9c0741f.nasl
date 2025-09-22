# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.681029990741102");
  script_cve_id("CVE-2024-31227", "CVE-2024-31228", "CVE-2024-31449");
  script_tag(name:"creation_date", value:"2024-10-14 04:08:40 +0000 (Mon, 14 Oct 2024)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-04 18:31:03 +0000 (Thu, 04 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-68f9c0741f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-68f9c0741f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-68f9c0741f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317403");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317407");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317413");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the FEDORA-2024-68f9c0741f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Redis Community Edition 7.2.6** Released Wed 02 Oct 2024 20:17:04 IDT


Upgrade urgency SECURITY: See security fixes below.

Security fixes

* **CVE-2024-31449** Lua library commands may lead to stack overflow and potential RCE.
* **CVE-2024-31227** Potential Denial-of-service due to malformed ACL selectors.
* **CVE-2024-31228** Potential Denial-of-service due to unbounded pattern matching.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.2.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~7.2.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~7.2.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-devel", rpm:"redis-devel~7.2.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-doc", rpm:"redis-doc~7.2.6~1.fc39", rls:"FC39"))) {
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
