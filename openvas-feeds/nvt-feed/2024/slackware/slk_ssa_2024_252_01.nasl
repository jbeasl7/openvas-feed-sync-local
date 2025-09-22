# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.252.01");
  script_cve_id("CVE-2015-2104", "CVE-2023-27043", "CVE-2024-28757", "CVE-2024-4032", "CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492", "CVE-2024-6232", "CVE-2024-6923", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2024-09-09 04:11:02 +0000 (Mon, 09 Sep 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-252-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-252-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.492660");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2024/09/python-3130rc2-3126-31110-31015-3920.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2015-2104");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-27043");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-28757");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-4032");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-45490");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-45491");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-45492");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-6232");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-6923");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-7592");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-8088");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SSA:2024-252-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New python3 packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/python3-3.9.20-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 Bundled libexpat was updated to 2.6.3.
 Fix quadratic complexity in parsing '-quoted cookie values with backslashes
 by http.cookies.
 Fixed various false positives and false negatives in IPv4Address.is_private,
 IPv4Address.is_global, IPv6Address.is_private, IPv6Address.is_global.
 Fix urllib.parse.urlunparse() and urllib.parse.urlunsplit() for URIs with
 path starting with multiple slashes and no authority.
 Remove backtracking from tarfile header parsing for hdrcharset, PAX, and
 GNU sparse headers.
 email.utils.getaddresses() and email.utils.parseaddr() now return ('', '')
 2-tuples in more situations where invalid email addresses are encountered
 instead of potentially inaccurate values. Add optional strict parameter to
 these two functions: use strict=False to get the old behavior, accept
 malformed inputs. getattr(email.utils, 'supports_strict_parsing', False) can
 be used to check if the strict paramater is available.
 Sanitize names in zipfile.Path to avoid infinite loops (gh-122905) without
 breaking contents using legitimate characters.
 Email headers with embedded newlines are now quoted on output. The generator
 will now refuse to serialize (write) headers that are unsafely folded or
 delimited, see verify_generated_headers.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'python3' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.20-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.20-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.11.10-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.11.10-x86_64-1", rls:"SLKcurrent"))) {
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
