# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.175.01");
  script_cve_id("CVE-2025-4877", "CVE-2025-4878", "CVE-2025-5318", "CVE-2025-5351", "CVE-2025-5372", "CVE-2025-5449", "CVE-2025-5987");
  script_tag(name:"creation_date", value:"2025-06-25 04:17:13 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-22 14:01:21 +0000 (Fri, 22 Aug 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-175-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-175-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.392586");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4877");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4878");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-5318");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-5351");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-5372");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-5449");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-5987");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the SSA:2025-175-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libssh packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libssh-0.11.2-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 Write beyond bounds in binary to base64 conversion.
 Use of uninitialized variable in privatekey_from_file().
 Likely read beyond bounds in sftp server handle management.
 Double free in functions exporting keys.
 ssh_kdf() returns a success code on certain failures.
 Likely read beyond bounds in sftp server message decoding.
 Invalid return code for chacha20 poly1305 with OpenSSL.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libssh' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"libssh", ver:"0.11.2-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libssh", ver:"0.11.2-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"libssh", ver:"0.11.2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libssh", ver:"0.11.2-x86_64-1", rls:"SLKcurrent"))) {
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
