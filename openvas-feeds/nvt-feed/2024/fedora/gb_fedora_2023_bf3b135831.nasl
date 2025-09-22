# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.98102398135831");
  script_cve_id("CVE-2020-12762");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-12 20:41:27 +0000 (Tue, 12 May 2020)");

  script_name("Fedora: Security Advisory (FEDORA-2023-bf3b135831)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-bf3b135831");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-bf3b135831");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2183193");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2203170");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libfastjson' package(s) announced via the FEDORA-2023-bf3b135831 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libfastjson-1.2304.0-1.fc39.

##### **Changelog**

```
* Tue May 16 2023 Attila Lakatos <alakatos@redhat.com> - 1.2304.0-1
- Rebase to 1.2304.0 (new release number scheme, now like rsyslog)
Resolves: rhbz#2183193
- Address CVE-2020-12762
Resolves: rhbz#2203170

```");

  script_tag(name:"affected", value:"'libfastjson' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"libfastjson", rpm:"libfastjson~1.2304.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfastjson-debuginfo", rpm:"libfastjson-debuginfo~1.2304.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfastjson-debugsource", rpm:"libfastjson-debugsource~1.2304.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfastjson-devel", rpm:"libfastjson-devel~1.2304.0~1.fc39", rls:"FC39"))) {
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
