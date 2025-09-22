# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58335");
  script_cve_id("CVE-2007-1286", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1521", "CVE-2007-1522", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1711", "CVE-2007-1718", "CVE-2007-1777", "CVE-2007-1824", "CVE-2007-1887", "CVE-2007-1889", "CVE-2007-1900");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-1283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1283-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1283-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-1283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in PHP, a server-side, HTML-embedded scripting language, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1286

Stefan Esser discovered an overflow in the object reference handling code of the unserialize() function, which allows the execution of arbitrary code if malformed input is passed from an application.

CVE-2007-1375

Stefan Esser discovered that an integer overflow in the substr_compare() function allows information disclosure of heap memory.

CVE-2007-1376

Stefan Esser discovered that insufficient validation of shared memory functions allows the disclosure of heap memory.

CVE-2007-1380

Stefan Esser discovered that the session handler performs insufficient validation of variable name length values, which allows information disclosure through a heap information leak.

CVE-2007-1453

Stefan Esser discovered that the filtering framework performs insufficient input validation, which allows the execution of arbitrary code through a buffer underflow.

CVE-2007-1454

Stefan Esser discovered that the filtering framework can be bypassed with a special whitespace character.

CVE-2007-1521

Stefan Esser discovered a double free vulnerability in the session_regenerate_id() function, which allows the execution of arbitrary code.

CVE-2007-1583

Stefan Esser discovered that a programming error in the mb_parse_str() function allows the activation of register_globals.

CVE-2007-1700

Stefan Esser discovered that the session extension incorrectly maintains the reference count of session variables, which allows the execution of arbitrary code.

CVE-2007-1711

Stefan Esser discovered a double free vulnerability in the session management code, which allows the execution of arbitrary code.

CVE-2007-1718

Stefan Esser discovered that the mail() function performs insufficient validation of folded mail headers, which allows mail header injection.

CVE-2007-1777

Stefan Esser discovered that the extension to handle ZIP archives performs insufficient length checks, which allows the execution of arbitrary code.

CVE-2007-1824

Stefan Esser discovered an off-by-one error in the filtering framework, which allows the execution of arbitrary code.

CVE-2007-1887

Stefan Esser discovered that a buffer overflow in the sqlite extension allows the execution of arbitrary code.

CVE-2007-1889

Stefan Esser discovered that the PHP memory manager performs an incorrect type cast, which allows the execution of arbitrary code through buffer overflows.

CVE-2007-1900

Stefan Esser discovered that incorrect validation in the email filter extension allows the injection of mail headers.

The oldstable distribution (sarge) doesn't include php5.

For the stable distribution (etch) these problems have been fixed in version 5.2.0-8+etch3.

For the unstable ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-php5", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.0-8+etch3", rls:"DEB4"))) {
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
