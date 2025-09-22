# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885570");
  script_cve_id("CVE-2023-41056");
  script_tag(name:"creation_date", value:"2024-01-18 09:16:32 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 16:15:46 +0000 (Wed, 10 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-6ef42a28c9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6ef42a28c9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6ef42a28c9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257454");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257455");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the FEDORA-2024-6ef42a28c9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Redis 7.2.4 ** Released Tue 09 Jan 2024 10:45:52 IST


Upgrade urgency SECURITY: See security fixes below.

Security fixes

* (**CVE-2023-41056**) In some cases, Redis may incorrectly handle resizing of memory
 buffers which can result in incorrect accounting of buffer sizes and lead to
 heap overflow and potential remote code execution.

Bug fixes

* Fix crashes of cluster commands clusters with mixed versions of 7.0 and 7.2 (#12805, #12832)
* Fix slot ownership not being properly handled when deleting a slot from a node (#12564)
* Fix atomicity issues with the RedisModuleEvent_Key module API event (#12733)");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.2.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~7.2.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~7.2.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-devel", rpm:"redis-devel~7.2.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-doc", rpm:"redis-doc~7.2.4~1.fc39", rls:"FC39"))) {
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
