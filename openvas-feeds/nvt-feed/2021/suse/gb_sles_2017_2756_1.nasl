# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2756.1");
  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7679", "CVE-2017-9788", "CVE-2017-9798");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-29 15:23:18 +0000 (Thu, 29 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2756-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2756-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172756-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980663");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003305.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2017:2756-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes several issues.

These security issues were fixed:

- CVE-2017-9798: Prevent use-after-free use of memory that allowed for an
 information leak via OPTIONS (bsc#1058058)
- CVE-2017-9788: Uninitialized memory reflection in mod_auth_digest could have
 lead to leakage of potentially confidential information, and a segfault in
 other cases resulting in DoS (bsc#1048576).
- CVE-2017-7679: mod_mime could have read one byte past the end of a buffer
 when sending a malicious Content-Type response header (bsc#1045060).
- CVE-2017-3169: mod_ssl may dereferenced a NULL pointer when third-party
 modules call ap_hook_process_connection() during an HTTP request to an HTTPS
 port allowing for DoS (bsc#1045062).
- CVE-2017-3167: Use of the ap_get_basic_auth_pw() by third-party modules
 outside of the authentication phase may have lead to authentication
 requirements being bypassed (bsc#1045065).

These non-security issues were fixed:

- remove /usr/bin/http2 symlink only during apache2 package
 uninstall, not upgrade (bsc#1041830)
- gensslcert: use hostname when fqdn is too long (bsc#1035829)
- add NotifyAccess=all to service file (bsc#980663)");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.10~14.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.10~14.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.10~14.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.10~14.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.10~14.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.10~14.28.1", rls:"SLES12.0"))) {
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
