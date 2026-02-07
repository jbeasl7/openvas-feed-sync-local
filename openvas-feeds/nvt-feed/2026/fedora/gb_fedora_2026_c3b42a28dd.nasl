# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.99398429728100100");
  script_cve_id("CVE-2026-24765");
  script_tag(name:"creation_date", value:"2026-02-06 04:37:17 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-c3b42a28dd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-c3b42a28dd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-c3b42a28dd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433680");
  script_xref(name:"URL", value:"https://github.com/php/php-src/actions/runs/21052584327/job/60542023395#step:14:3729");
  script_xref(name:"URL", value:"https://github.com/sebastianbergmann/phpunit/issues/6362");
  script_xref(name:"URL", value:"https://github.com/sebastianbergmann/phpunit/issues/6470");
  script_xref(name:"URL", value:"https://phpunit.expert/articles/how-php-and-its-ecosystem-test-each-other.html?ref=github");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpunit11' package(s) announced via the FEDORA-2026-c3b42a28dd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## Version 11.5.50 - 2026-01-27

### Changed

* To prevent Poisoned Pipeline Execution (PPE) attacks using prepared `.coverage` files in pull requests, a PHPT test will no longer be run if the temporary file for writing code coverage information already exists before the test runs



----

## Version 11.5.49 - 2026-01-24

### Fixed

* [#6362]([link moved to references]): Manually instantiated test doubles are broken since PHPUnit 11.2
* [#6470]([link moved to references]): Infinite recursion in `Count::getCountOf()` for unusal implementations of `Iterator` or `IteratorAggregate`



----

## Version 11.5.48 - 2026-01-16

### Changed

* Reverted a change that caused a [build failure]([link moved to references]) for the [PHP project's nightly community job]([link moved to references])


----

## Version 11.5.47 - 2026-01-15

### Fixed

* [#6470]([link moved to references]): Mocking a class with a property hook setter accepting more types than the property results in a fatal error");

  script_tag(name:"affected", value:"'phpunit11' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpunit11", rpm:"phpunit11~11.5.50~1.fc42", rls:"FC42"))) {
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
