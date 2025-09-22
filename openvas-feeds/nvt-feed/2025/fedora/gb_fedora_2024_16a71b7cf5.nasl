# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.169771987991025");
  script_cve_id("CVE-2024-50342");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-16a71b7cf5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-16a71b7cf5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-16a71b7cf5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324261");
  script_xref(name:"URL", value:"https://github.com/llaville/box-manifest/issues/13");
  script_xref(name:"URL", value:"https://github.com/llaville/box-manifest/releases/tag/4.0.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-bartlett-PHP-CompatInfo' package(s) announced via the FEDORA-2024-16a71b7cf5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**bartlett/php-compatinfo-db 6.12.0** - 2024-10-29

Added

- `db:show` command is now able to display deprecations on all components
- PHP 8.2.25 support
- PHP 8.3.13 support
- PHP 8.4.0 support (until RC3)

Changed

- update `mailparse` reference to version 3.1.8
- update `oauth` reference to version 2.0.9
- update `oci8` reference to version 3.4.0
- update `rdkafka` reference to version 6.0.4
- update `redis` reference to version 6.1.0
- update `uuid` reference to version 1.2.1
- update `xdebug` reference to version 3.4.0beta1
- update `yaml` reference to version 2.2.4

----

**bartlett/php-compatinfo-db 6.11.1** - 2024-10-04

Changed

- update `opentelemetry` reference to version 1.1.0 (stable)

Fixed

- PHAR distribution was broken (reason is [issue]([link moved to references])
 explained into BOX Manifest 4.0.0RC1).
 Solved now, we use the final stable version [4.0.0]([link moved to references])

----

**bartlett/php-compatinfo-db 6.11.0** - 2024-10-02

Added

- PHP 8.1.30 support
- PHP 8.2.24 support
- PHP 8.3.12 support
- `mongodb` extension support
- `xpass` extension support

Changed

- update `apcu` reference to version 5.1.24
- update `msgpack` reference to version 3.0.0
- update `opentelemetry` reference to version 1.1.0beta3
- update `xlswriter` reference to version 1.5.7
- update `zip` reference to version 1.22.4
- mongo extension is marked now as not supported (superseded by mongodb reference that is now available)

----

**bartlett/php-compatinfo-db 6.10.0** - 2024-09-01

Added

- PHP 8.2.23 support
- PHP 8.3.11 support

Changed

- update `xlswriter` reference to version 1.5.6

----

**bartlett/php-compatinfo-db 6.9.0** - 2024-08-17

Added

- PHP 8.2.22 support
- PHP 8.3.10 support

Changed

- update `ast` reference to version 1.1.2
- update `igbinary` reference to version 3.2.16

----

**bartlett/php-compatinfo-db 6.8.0** - 2024-07-16

Added

- PHP 8.2.21 support
- PHP 8.3.9 support

Changed

- update xhprof reference to version 2.3.10

----

**bartlett/php-compatinfo-db 6.7.0** - 2024-06-14

Added

- PHP 8.1.29 support
- PHP 8.2.20 support
- PHP 8.3.8 support

----

**bartlett/php-compatinfo-db 6.6.0** - 2024-05-13

Added

- PHP 8.1.28 support
- PHP 8.2.19 support
- PHP 8.3.7 support

Changed

- update opentelemetry reference to version 1.0.3
- update xdebug reference to version 3.3.2");

  script_tag(name:"affected", value:"'php-bartlett-PHP-CompatInfo' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-bartlett-PHP-CompatInfo", rpm:"php-bartlett-PHP-CompatInfo~7.1.4~3.fc41", rls:"FC41"))) {
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
