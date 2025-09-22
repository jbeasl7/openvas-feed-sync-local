# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9783510010004970");
  script_cve_id("CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a835dd04a0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a835dd04a0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a835dd04a0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310136");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310146");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310152");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334236");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlrpc-c' package(s) announced via the FEDORA-2025-a835dd04a0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for xmlrpc-c-1.60.04-2.fc42.

##### **Changelog**

```
* Thu Jan 2 2025 Jonathan Wright <jonathan@almalinux.org> - 1.60.4-2
- Use global macro to override make smp_flags
* Thu Jan 2 2025 Jonathan Wright <jonathan@almalinux.org> - 1.60.4-1
- update to 1.60.4 rhbz#2334236
- re-enable builds against libxml2, no more bundled libexpat
- fixes rhbz#2310136
- fixes rhbz#2310146
- fixes rhbz#2310152
* Wed Sep 4 2024 Miroslav Suchy <msuchy@redhat.com> - 1.59.03-3
- convert license to SPDX

```

----

Automatic update for xmlrpc-c-1.60.04-1.fc42.");

  script_tag(name:"affected", value:"'xmlrpc-c' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c", rpm:"xmlrpc-c~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-apps", rpm:"xmlrpc-c-apps~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-apps-debuginfo", rpm:"xmlrpc-c-apps-debuginfo~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-c++", rpm:"xmlrpc-c-c++~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-c++-debuginfo", rpm:"xmlrpc-c-c++-debuginfo~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-client++", rpm:"xmlrpc-c-client++~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-client++-debuginfo", rpm:"xmlrpc-c-client++-debuginfo~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-client", rpm:"xmlrpc-c-client~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-client-debuginfo", rpm:"xmlrpc-c-client-debuginfo~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-debuginfo", rpm:"xmlrpc-c-debuginfo~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-debugsource", rpm:"xmlrpc-c-debugsource~1.60.04~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlrpc-c-devel", rpm:"xmlrpc-c-devel~1.60.04~2.fc42", rls:"FC42"))) {
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
