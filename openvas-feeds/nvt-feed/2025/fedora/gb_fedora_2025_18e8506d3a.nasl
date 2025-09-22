# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.181018506100397");
  script_cve_id("CVE-2025-4877", "CVE-2025-4878", "CVE-2025-5318", "CVE-2025-5351", "CVE-2025-5372", "CVE-2025-5449", "CVE-2025-5987");
  script_tag(name:"creation_date", value:"2025-08-07 04:20:21 +0000 (Thu, 07 Aug 2025)");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-22 14:01:21 +0000 (Fri, 22 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-18e8506d3a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-18e8506d3a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-18e8506d3a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374586");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376224");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2382566");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the FEDORA-2025-18e8506d3a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release with security fixes for CVE-2025-4877, CVE-2025-4878, CVE-2025-5987, CVE-2025-5318, CVE-2025-5351, CVE-2025-5372, CVE-2025-5449

----

Automatic update for libssh-0.11.0-1.fc41.");

  script_tag(name:"affected", value:"'libssh' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.11.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.11.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-debuginfo", rpm:"libssh-debuginfo~0.11.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-debugsource", rpm:"libssh-debugsource~0.11.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.11.2~1.fc41", rls:"FC41"))) {
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
