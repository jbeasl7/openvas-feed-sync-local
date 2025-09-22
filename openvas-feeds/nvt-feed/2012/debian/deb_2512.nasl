# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71488");
  script_cve_id("CVE-2012-3382");
  script_tag(name:"creation_date", value:"2012-08-10 07:12:04 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2512-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2512-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2512");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mono' package(s) announced via the DSA-2512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcus Meissner discovered that the web server included in Mono performed insufficient sanitising of requests, resulting in cross-site scripting.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.7-5.1.

For the unstable distribution (sid), this problem has been fixed in version 2.10.8.1-5.

We recommend that you upgrade your mono packages.");

  script_tag(name:"affected", value:"'mono' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-c5-1.1-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-debugger-soft0.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-dev", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-getoptions1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-getoptions2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-management2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-profiler", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-rabbitmq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-simd2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-linq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-tasklets2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-wcf3.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webbrowser0.5-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-windowsbase3.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono0", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono0-dbg", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-gac", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-service", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-complete", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-dbg", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-devel", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gac", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-jay", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mcs", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mjs", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-utils", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-base", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-manual", ver:"2.6.7-5.1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"prj2make-sharp", ver:"2.6.7-5.1", rls:"DEB6"))) {
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
