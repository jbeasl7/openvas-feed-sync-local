# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67264");
  script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"creation_date", value:"2010-04-21 01:31:17 +0000 (Wed, 21 Apr 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2028-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2028-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2028-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2028");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xpdf' package(s) announced via the DSA-2028-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in xpdf, a suite of tools for viewing and converting Portable Document Format (PDF) files.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1188 and CVE-2009-3603 Integer overflow in SplashBitmap::SplashBitmap which might allow remote attackers to execute arbitrary code or an application crash via a crafted PDF document.

CVE-2009-3604

NULL pointer dereference or heap-based buffer overflow in Splash::drawImage which might allow remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted PDF document.

CVE-2009-3606

Integer overflow in the PSOutputDev::doImageL1Sep which might allow remote attackers to execute arbitrary code via a crafted PDF document.

CVE-2009-3608

Integer overflow in the ObjectStream::ObjectStream which might allow remote attackers to execute arbitrary code via a crafted PDF document.

CVE-2009-3609

Integer overflow in the ImageStream::ImageStream which might allow remote attackers to cause a denial of service via a crafted PDF document.

For the stable distribution (lenny), this problem has been fixed in version 3.02-1.4+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 3.02-2.");

  script_tag(name:"affected", value:"'xpdf' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny2", rls:"DEB5"))) {
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
