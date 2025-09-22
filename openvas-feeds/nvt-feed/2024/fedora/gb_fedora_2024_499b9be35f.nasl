# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885812");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679");
  script_tag(name:"creation_date", value:"2024-02-26 02:03:53 +0000 (Mon, 26 Feb 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:45 +0000 (Tue, 13 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-499b9be35f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-499b9be35f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-499b9be35f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264048");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-4408");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-50387");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-5517");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-5679");
  script_xref(name:"URL", value:"https://www.isc.org/blogs/2024-bind-security-release/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next' package(s) announced via the FEDORA-2024-499b9be35f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Security Fixes

- Validating DNS messages containing a lot of DNSSEC signatures could cause excessive CPU load, leading to a denial-of-service condition. This has been fixed. ([CVE-2023-50387]([link moved to references]))

 ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel, and Michael Waidner from the German National Research Center for Applied Cybersecurity ATHENE for bringing this vulnerability to our attention. [GL #4424]

- Parsing DNS messages with many different names could cause excessive CPU load. This has been fixed. ([CVE-2023-4408]([link moved to references]))

 ISC would like to thank Shoham Danino from Reichman University, Anat Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv University, and Yuval Shavitt from Tel-Aviv University for bringing this vulnerability to our attention. [GL #4234]

- Specific queries could cause named to crash with an assertion failure when nxdomain-redirect was enabled. This has been fixed. ([CVE-2023-5517]([link moved to references])) [GL #4281]

- A bad interaction between DNS64 and serve-stale could cause named to crash with an assertion failure, when both of these features were enabled. This has been fixed. ([CVE-2023-5679]([link moved to references])) [GL #4334]

## Related blog post

- [BIND 9 Security Release and Multi-Vendor Vulnerability Handling, CVE-2023-50387 and CVE-2023-50868]([link moved to references])");

  script_tag(name:"affected", value:"'bind9-next' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind9-next", rpm:"bind9-next~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-chroot", rpm:"bind9-next-chroot~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debuginfo", rpm:"bind9-next-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debugsource", rpm:"bind9-next-debugsource~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-devel", rpm:"bind9-next-devel~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-filesystem", rpm:"bind9-next-dlz-filesystem~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-filesystem-debuginfo", rpm:"bind9-next-dlz-filesystem-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-ldap", rpm:"bind9-next-dlz-ldap~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-ldap-debuginfo", rpm:"bind9-next-dlz-ldap-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-mysql", rpm:"bind9-next-dlz-mysql~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-mysql-debuginfo", rpm:"bind9-next-dlz-mysql-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-sqlite3", rpm:"bind9-next-dlz-sqlite3~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-sqlite3-debuginfo", rpm:"bind9-next-dlz-sqlite3-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils", rpm:"bind9-next-dnssec-utils~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils-debuginfo", rpm:"bind9-next-dnssec-utils-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-doc", rpm:"bind9-next-doc~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs", rpm:"bind9-next-libs~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs-debuginfo", rpm:"bind9-next-libs-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-license", rpm:"bind9-next-license~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils", rpm:"bind9-next-utils~9.19.21~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils-debuginfo", rpm:"bind9-next-utils-debuginfo~9.19.21~1.fc39", rls:"FC39"))) {
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
