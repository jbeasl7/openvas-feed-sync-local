# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56664");
  script_cve_id("CVE-2005-4134", "CVE-2005-4720", "CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1044-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1044-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1044");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-1044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla Firefox. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

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

CVE-2006-1727

Georgi Guninski reported two variants of using scripts in an XBL control to gain chrome privileges when the page is viewed under 'Print Preview'. [MFSA-2006-25]

CVE-2006-1728

'shutdown' discovered that the crypto.generateCRMFRequest method can be used to run arbitrary code with the privilege of the user running the browser, which could enable an attacker to install malware. [MFSA-2006-24]

CVE-2006-1729

Claus Jorgensen reported that a text input box can be pre-filled with a filename and then turned into a file-upload control, allowing a malicious website to steal any local file whose name they can guess. [MFSA-2006-23]

CVE-2006-1730

An anonymous researcher for TippingPoint and the Zero Day Initiative discovered an integer overflow triggered by the CSS letter-spacing property, which could be exploited to execute arbitrary code. [MFSA-2006-22]

CVE-2006-1731

'moz_bug_r_a4' discovered that some internal functions return prototypes instead of objects, which allows remote attackers to conduct cross-site scripting attacks. [MFSA-2006-19]

CVE-2006-1732

'shutdown' discovered that it is possible to bypass same-origin protections, allowing a malicious site to inject script into content from another site, which could allow the malicious page to steal information such as cookies or passwords from the other site, or perform transactions on the user's behalf if the user were already logged in. [MFSA-2006-17]

CVE-2006-1733

'moz_bug_r_a4' discovered that the compilation scope of privileged built-in XBL bindings is not fully protected from web content and can still be executed which could be used to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge6", rls:"DEB3.1"))) {
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
