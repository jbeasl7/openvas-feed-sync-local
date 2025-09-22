# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123697");
  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:22 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0500");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0500.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the ELSA-2013-0500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.12.4-4]
- Applied patch to fix CVE-2013-0200, temporary file vulnerability
 (bug #902163).
- Fixed hpijs-marker-supply patch.

[3.12.4-3]
- Make 'hp-check' check for hpaio set-up correctly (bug #683007).

[3.12.4-2]
- Added more fixes from Fedora (bug #731900).

[3.12.4-1]
- Re-based to 3.12.4 with fixes from Fedora (bug #731900). No longer
 need no-system-tray, openPPD, addgroup, emit-SIGNAL, fab-root-crash,
 newline, hpaio-segfault, dbus-threads, or cups-web patches.

[3.10.9-4]
- The hpijs sub-package no longer requires cupsddk-drivers (which no
 longer exists as a real package), but cups >= 1.4 (bug #829453).");

  script_tag(name:"affected", value:"'hplip' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~3.12.4~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-common", rpm:"hplip-common~3.12.4~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-libs", rpm:"hplip-libs~3.12.4~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane-hpaio", rpm:"libsane-hpaio~3.12.4~4.el6", rls:"OracleLinux6"))) {
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
