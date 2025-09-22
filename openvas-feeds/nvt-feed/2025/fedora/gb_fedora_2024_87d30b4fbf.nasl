# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.871003098410298102");
  script_cve_id("CVE-2024-32002", "CVE-2024-32004", "CVE-2024-32020", "CVE-2024-32021", "CVE-2024-32465", "CVE-2024-41123", "CVE-2024-43398");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 20:40:28 +0000 (Thu, 23 May 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-87d30b4fbf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-87d30b4fbf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-87d30b4fbf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280426");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280433");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280449");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280455");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280469");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280475");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280487");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280939");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301323");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302835");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307674");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_41_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'swiftlint' package(s) announced via the FEDORA-2024-87d30b4fbf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for swiftlint-0.57.1-1.fc42.

##### **Changelog**

```
* Fri Dec 20 2024 Davide Cavalca <dcavalca@fedoraproject.org> - 0.57.1-1
- Update to 0.57.1, Fixes: RHBZ#2280939, RHBZ#2301323, RHBZ#2280426,
 RHBZ#2280433, RHBZ#2280449, RHBZ#2280455, RHBZ#2280469, RHBZ#2280475,
 RHBZ#2280487, RHBZ#2302835, RHBZ#2307674
* Sat Jul 20 2024 Fedora Release Engineering <releng@fedoraproject.org> - 0.53.0-5
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'swiftlint' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"swiftlint", rpm:"swiftlint~0.57.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"swiftlint-debuginfo", rpm:"swiftlint-debuginfo~0.57.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"swiftlint-debugsource", rpm:"swiftlint-debugsource~0.57.1~1.fc42", rls:"FC42"))) {
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
