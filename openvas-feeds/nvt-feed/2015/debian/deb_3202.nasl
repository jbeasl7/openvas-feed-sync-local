# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703202");
  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_tag(name:"creation_date", value:"2015-03-21 23:00:00 +0000 (Sat, 21 Mar 2015)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-30 19:21:04 +0000 (Tue, 30 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3202-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3202-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3202");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mono' package(s) announced via the DSA-3202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Researchers at INRIA and Xamarin discovered several vulnerabilities in mono, a platform for running and developing applications based on the ECMA/ISO Standards. Mono's TLS stack contained several problems that hampered its capabilities: those issues could lead to client impersonation (via SKIP-TLS), SSLv2 fallback, and encryption weakening (via FREAK).

For the stable distribution (wheezy), these problems have been fixed in version 2.10.8.1-8+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 3.2.8+dfsg-10.

We recommend that you upgrade your mono packages.");

  script_tag(name:"affected", value:"'mono' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-2.0-1", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-2.0-1-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-2.0-dev", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-c5-1.1-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-codecontracts4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-compilerservices-symbolwriter4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-csharp4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-custommarshalers4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-debugger-soft2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-debugger-soft4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-http4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-cjk4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-mideast4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-other4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-rare4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n4.0-all", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-management2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-management4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-engine4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-framework4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-tasks-v4.0-4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-utilities-v4.0-4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-csharp4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-visualc10.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-web-infrastructure1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-opensystem-c4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-profiler", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-rabbitmq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-rabbitmq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip4.84-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-simd2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-simd4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-componentmodel-composition4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-componentmodel-dataannotations4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-configuration-install4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-configuration4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-core4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-datasetextensions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-linq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-linq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-services-client4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-services4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-drawing-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-drawing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-dynamic4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-enterpriseservices4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-identitymodel-selectors4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-identitymodel4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-management4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-net4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-numerics4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-caching4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-durableinstancing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-serialization-formatters-soap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-serialization4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-security4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-discovery4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-routing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-serviceprocess4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-transactions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-abstractions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-applicationservices4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-dynamicdata4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-extensions-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-extensions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-routing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-services4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-windows-forms-datavisualization4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-windows-forms4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xaml4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xml-linq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xml4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-tasklets2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-tasklets4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-wcf3.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webbrowser2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webbrowser4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webmatrix-data4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-windowsbase3.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-windowsbase4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-4.0-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-4.0-service", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-complete", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-devel", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-dmcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-jay", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-sgen", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-utils", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-base", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-manual", ver:"2.10.8.1-8+deb7u1", rls:"DEB7"))) {
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
