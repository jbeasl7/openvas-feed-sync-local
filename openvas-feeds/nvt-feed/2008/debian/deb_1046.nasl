# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56667");
  script_cve_id("CVE-2005-2353", "CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1046-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1046-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1046-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1046");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla' package(s) announced via the DSA-1046-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2005-2353

The 'run-mozilla.sh' script allows local users to create or overwrite arbitrary files when debugging is enabled via a symlink attack on temporary files.

CVE-2005-4134

Web pages with extremely long titles cause subsequent launches of the browser to appear to 'hang' for up to a few minutes, or even crash if the computer has insufficient memory. [MFSA-2006-03]

CVE-2006-0292

The JavaScript interpreter does not properly dereference objects, which allows remote attackers to cause a denial of service or execute arbitrary code. [MFSA-2006-01]

CVE-2006-0293

The function allocation code allows attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-01]

CVE-2006-0296

XULDocument.persist() did not validate the attribute name, allowing an attacker to inject arbitrary XML and JavaScript code into localstore.rdf that would be read and acted upon during startup. [MFSA-2006-05]

CVE-2006-0748

An anonymous researcher for TippingPoint and the Zero Day Initiative reported that an invalid and nonsensical ordering of table-related tags can be exploited to execute arbitrary code. [MFSA-2006-27]

CVE-2006-0749

A particular sequence of HTML tags can cause memory corruption that can be exploited to execute arbitrary code. [MFSA-2006-18]

CVE-2006-0884

Georgi Guninski reports that forwarding mail in-line while using the default HTML 'rich mail' editor will execute JavaScript embedded in the e-mail message with full privileges of the client. [MFSA-2006-21]

CVE-2006-1045

The HTML rendering engine does not properly block external images from inline HTML attachments when 'Block loading of remote images in mail messages' is enabled, which could allow remote attackers to obtain sensitive information. [MFSA-2006-26]

CVE-2006-1529

A vulnerability potentially allows remote attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-20]

CVE-2006-1530

A vulnerability potentially allows remote attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-20]

CVE-2006-1531

A vulnerability potentially allows remote attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-20]

CVE-2006-1723

A vulnerability potentially allows remote attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-20]

CVE-2006-1724

A vulnerability potentially allows remote attackers to cause a denial of service and possibly execute arbitrary code. [MFSA-2006-20]

CVE-2006-1725

Due to an interaction between XUL content windows and the history mechanism, some windows may to become translucent, which might allow remote attackers to execute arbitrary code. [MFSA-2006-29]

CVE-2006-1726

'shutdown' discovered ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr-dev", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dev", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.7.8-1sarge5", rls:"DEB3.1"))) {
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
