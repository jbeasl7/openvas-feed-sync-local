# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.429713102896101");
  script_cve_id("CVE-2025-3576");
  script_tag(name:"creation_date", value:"2025-06-10 04:09:43 +0000 (Tue, 10 Jun 2025)");
  script_version("2025-06-10T05:40:17+0000");
  script_tag(name:"last_modification", value:"2025-06-10 05:40:17 +0000 (Tue, 10 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 06:15:44 +0000 (Tue, 15 Apr 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-42a13f896e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-42a13f896e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-42a13f896e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357215");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359673");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370259");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the FEDORA-2025-42a13f896e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Disallowing use of the `arcfour-hmac(-md5)` encryption type for session keys
* Add support for the PKINIT paChecksum2 sequence, required for Active Directory interoperability on Windows Server 2025
* Fix generation of RADIUS Message-Authenticator in FIPS mode");

  script_tag(name:"affected", value:"'krb5' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs-debuginfo", rpm:"krb5-libs-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-debuginfo", rpm:"krb5-pkinit-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap-debuginfo", rpm:"krb5-server-ldap-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-tests", rpm:"krb5-tests~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation-debuginfo", rpm:"krb5-workstation-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkadm5", rpm:"libkadm5~1.21.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkadm5-debuginfo", rpm:"libkadm5-debuginfo~1.21.3~5.fc41", rls:"FC41"))) {
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
