# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885138");
  script_cve_id("CVE-2023-45145");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:01 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-30 12:50:12 +0000 (Mon, 30 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-fd75e4f307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-fd75e4f307");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-fd75e4f307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244940");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244942");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the FEDORA-2023-fd75e4f307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Redis 7.2.2** Released Wed 18 Oct 2023 10:33:40 IDT

Upgrade urgency SECURITY: See security fixes below.

Security fixes

* (**CVE-2023-45145**) The wrong order of listen(2) and chmod(2) calls creates a
 race condition that can be used by another process to bypass desired Unix
 socket permissions on startup.

Bug fixes

* WAITAOF could timeout in the absence of write traffic in case a new AOF is
 created and an AOF rewrite can't immediately start (#12620)

Redis cluster

* Fix crash when running rebalance command in a mixed cluster of 7.0 and 7.2
 nodes (#12604)
* Fix the return type of the slot number in cluster shards to integer, which
 makes it consistent with past behavior (#12561)
* Fix CLUSTER commands are called from modules or scripts to return TLS info
 appropriately (#12569)

Changes in CLI tools

* redis-cli, fix crash on reconnect when in SUBSCRIBE mode (#12571)

Module API changes

* Fix overflow calculation for next timer event (#12474)");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~7.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~7.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-devel", rpm:"redis-devel~7.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-doc", rpm:"redis-doc~7.2.2~1.fc39", rls:"FC39"))) {
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
