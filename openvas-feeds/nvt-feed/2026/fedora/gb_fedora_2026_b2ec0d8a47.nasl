# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.98210199010089747");
  script_cve_id("CVE-2026-1519");
  script_tag(name:"creation_date", value:"2026-03-30 04:59:52 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 14:16:33 +0000 (Wed, 25 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-b2ec0d8a47)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-b2ec0d8a47");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-b2ec0d8a47");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2440561");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451360");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.18.47/doc/arm/html/notes.html#notes-for-bind-9-18-47");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind, bind-dyndb-ldap' package(s) announced via the FEDORA-2026-b2ec0d8a47 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 9.18.47 (rhbz#2440561)

## Security Fixes:

- Fix unbounded NSEC3 iterations when validating referrals to unsigned delegations. (CVE-2026-1519)

Source: [link moved to references]");

  script_tag(name:"affected", value:"'bind, bind-dyndb-ldap' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils-debuginfo", rpm:"bind-dnssec-utils-debuginfo~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~11.11~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debuginfo", rpm:"bind-dyndb-ldap-debuginfo~11.11~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debugsource", rpm:"bind-dyndb-ldap-debugsource~11.11~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.18.47~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.18.47~1.fc43", rls:"FC43"))) {
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
