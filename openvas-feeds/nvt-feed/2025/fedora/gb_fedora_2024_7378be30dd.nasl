# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.73789810130100100");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679", "CVE-2023-6516");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:46 +0000 (Tue, 13 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-7378be30dd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7378be30dd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7378be30dd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255407");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264032");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264062");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264063");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264064");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264065");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264067");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264068");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.18.24/doc/arm/html/notes.html#notes-for-bind-9-18-24");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-4408");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-50387");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-5517");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-5679");
  script_xref(name:"URL", value:"https://www.isc.org/blogs/2024-bind-security-release/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind, bind-dyndb-ldap' package(s) announced via the FEDORA-2024-7378be30dd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Security Fixes

- Validating DNS messages containing a lot of DNSSEC signatures could cause excessive CPU load, leading to a denial-of-service condition. This has been fixed. ([CVE-2023-50387]([link moved to references]))

 ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel, and Michael Waidner from the German National Research Center for Applied Cybersecurity ATHENE for bringing this vulnerability to our attention. [GL #4424]

- Parsing DNS messages with many different names could cause excessive CPU load. This has been fixed. ([CVE-2023-4408]([link moved to references]))

 ISC would like to thank Shoham Danino from Reichman University, Anat Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv University, and Yuval Shavitt from Tel-Aviv University for bringing this vulnerability to our attention. [GL #4234]

- Specific queries could cause named to crash with an assertion failure when nxdomain-redirect was enabled. This has been fixed. ([CVE-2023-5517]([link moved to references])) [GL #4281]

- A bad interaction between DNS64 and serve-stale could cause named to crash with an assertion failure, when both of these features were enabled. This has been fixed. ([CVE-2023-5679]([link moved to references])) [GL #4334]

- Under certain circumstances, the DNS-over-TLS client code incorrectly attempted to process more than one DNS message at a time, which could cause named to crash with an assertion failure. This has been fixed. [GL #4487]

- Full [Release notes]([link moved to references])

## Related blog post

- [BIND 9 Security Release and Multi-Vendor Vulnerability Handling, CVE-2023-50387 and CVE-2023-50868]([link moved to references])");

  script_tag(name:"affected", value:"'bind, bind-dyndb-ldap' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem", rpm:"bind-dlz-filesystem~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem-debuginfo", rpm:"bind-dlz-filesystem-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap", rpm:"bind-dlz-ldap~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap-debuginfo", rpm:"bind-dlz-ldap-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql", rpm:"bind-dlz-mysql~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql-debuginfo", rpm:"bind-dlz-mysql-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3", rpm:"bind-dlz-sqlite3~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3-debuginfo", rpm:"bind-dlz-sqlite3-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils-debuginfo", rpm:"bind-dnssec-utils-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~11.10~27.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debuginfo", rpm:"bind-dyndb-ldap-debuginfo~11.10~27.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debugsource", rpm:"bind-dyndb-ldap-debugsource~11.10~27.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.18.24~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.18.24~1.fc41", rls:"FC41"))) {
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
