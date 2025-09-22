# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.102970999898557");
  script_cve_id("CVE-2023-26302");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 16:28:43 +0000 (Mon, 06 Mar 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-f970cbb557)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-f970cbb557");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-f970cbb557");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2172373");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177154");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-markdown-it-py' package(s) announced via the FEDORA-2023-f970cbb557 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for python-markdown-it-py-2.2.0-1.fc39.

##### **Changelog**

```
* Wed Mar 15 2023 Karolina Surma <ksurma@redhat.com> - 2.2.0-1
- Update to 2.2.0, includes the fix for CVE-2023-26302
Resolves: rhbz#2172373 rhbz#2177154
- Provide extra subpackages: linkify and plugins

```");

  script_tag(name:"affected", value:"'python-markdown-it-py' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-markdown-it-py", rpm:"python-markdown-it-py~2.2.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-markdown-it-py+linkify", rpm:"python3-markdown-it-py+linkify~2.2.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-markdown-it-py+plugins", rpm:"python3-markdown-it-py+plugins~2.2.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-markdown-it-py", rpm:"python3-markdown-it-py~2.2.0~1.fc39", rls:"FC39"))) {
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
