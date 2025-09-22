# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.6100101102755315");
  script_cve_id("CVE-2023-27043", "CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-6def755315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6def755315");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6def755315");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307370");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307461");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.utils.html#email.utils.getaddresses");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.utils.html#email.utils.parseaddr");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/http.cookies.html#module-http.cookies");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/zipfile.html#zipfile.Path");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/102988");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/121285");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122905");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123067");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123270");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.12' package(s) announced via the FEDORA-2024-6def755315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the sixth maintenance release of Python 3.12
====================================================

Python 3.12 is the newest major release of the Python programming language, and it contains many new features and optimizations. 3.12.6 is the latest maintenance release, containing about 90 bugfixes, build improvements and documentation changes since 3.12.5. This is an expedited release to address the following security issues:

- [gh-123067]([link moved to references]): Fix quadratic complexity in parsing `'`-quoted cookie values with backslashes by [`http.cookies`]([link moved to references]). Fixes CVE-2024-7592.
- [gh-121285]([link moved to references]): Remove backtracking from tarfile header parsing for `hdrcharset`, PAX, and GNU sparse headers. That's CVE-2024-6232.
- [gh-102988]([link moved to references]): [`email.utils.getaddresses()`]([link moved to references]) and [`email.utils.parseaddr()`]([link moved to references]) now return `('', '')` 2-tuples in more situations where invalid email addresses are encountered instead of potentially inaccurate values. Add optional *strict* parameter to these two functions: use `strict=False` to get the old behavior, accept malformed inputs. `getattr(email.utils, 'supports_strict_parsing', False)` can be use to check if the *strict* paramater is available. This improves the CVE-2023-27043 fix.
- [gh-123270]([link moved to references]): Sanitize names in [`zipfile.Path`]([link moved to references]) to avoid infinite loops ([gh-122905]([link moved to references])) without breaking contents using legitimate characters. That's CVE-2024-8088.");

  script_tag(name:"affected", value:"'python3.12' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"python3.12", rpm:"python3.12~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debug", rpm:"python3.12-debug~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debuginfo", rpm:"python3.12-debuginfo~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debugsource", rpm:"python3.12-debugsource~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-devel", rpm:"python3.12-devel~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-idle", rpm:"python3.12-idle~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-libs", rpm:"python3.12-libs~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-test", rpm:"python3.12-test~3.12.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-tkinter", rpm:"python3.12-tkinter~3.12.6~1.fc41", rls:"FC41"))) {
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
