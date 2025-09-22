# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.569849901024994");
  script_tag(name:"creation_date", value:"2025-06-16 04:13:00 +0000 (Mon, 16 Jun 2025)");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-56b4c0f4c4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-56b4c0f4c4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-56b4c0f4c4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.11' package(s) announced via the FEDORA-2025-56b4c0f4c4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 3.11.13.

 - gh-135034: [CVE 2024-12718] [CVE 2025-4138] [CVE 2025-4330] [CVE 2025-4435] [CVE 2025-4517] Fixes multiple issues that allowed tarfile extraction filters (filter='data' and filter='tar') to be bypassed using crafted symlinks and hard links.
 - gh-133767: Fix use-after-free in the 'unicode-escape' decoder with a non-'strict' error handler.
 - gh-128840: Short-circuit the processing of long IPv6 addresses early in ipaddress to prevent excessive memory consumption and a minor denial-of-service.");

  script_tag(name:"affected", value:"'python3.11' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.11", rpm:"python3.11~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debug", rpm:"python3.11-debug~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debuginfo", rpm:"python3.11-debuginfo~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debugsource", rpm:"python3.11-debugsource~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-devel", rpm:"python3.11-devel~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-idle", rpm:"python3.11-idle~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-libs", rpm:"python3.11-libs~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-test", rpm:"python3.11-test~3.11.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-tkinter", rpm:"python3.11-tkinter~3.11.13~1.fc41", rls:"FC41"))) {
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
