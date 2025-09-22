# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.140.01");
  script_cve_id("CVE-2025-4802");
  script_tag(name:"creation_date", value:"2025-05-26 10:52:59 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-140-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2025-140-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.470643");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4802");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SSA:2025-140-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New glibc packages are available for Slackware 15.0 to fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/aaa_glibc-solibs-2.33-i586-8_slack15.0.txz: Rebuilt.
patches/packages/glibc-2.33-i586-8_slack15.0.txz: Rebuilt.
 This update fixes a security issue:
 elf: static setuid binary dlopen may incorrectly search LD_LIBRARY_PATH.
 A statically linked setuid binary that calls dlopen (including internal
 dlopen calls after setlocale or calls to NSS functions such as getaddrinfo)
 may incorrectly search LD_LIBRARY_PATH to determine which library to load,
 leading to the execution of library code that is attacker controlled.
 The only viable vector for exploitation of this bug is local, if a static
 setuid program exists, and that program calls dlopen, then it may search
 LD_LIBRARY_PATH to locate the SONAME to load. No such program has been
 discovered at the time of publishing this advisory, but the presence of
 custom setuid programs, although strongly discouraged as a security
 practice, cannot be discounted.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/glibc-i18n-2.33-i586-8_slack15.0.txz: Rebuilt.
patches/packages/glibc-profile-2.33-i586-8_slack15.0.txz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'glibc' package(s) on Slackware 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"aaa_glibc-solibs", ver:"2.33-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"aaa_glibc-solibs", ver:"2.33-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.33-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.33-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.33-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.33-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.33-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.33-x86_64-8_slack15.0", rls:"SLK15.0"))) {
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
