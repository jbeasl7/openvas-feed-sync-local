# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68458");
  script_cve_id("CVE-2010-0654", "CVE-2010-2769", "CVE-2010-3174", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3183", "CVE-2010-3765");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2124-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2124-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2124");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-2124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Xulrunner, the component that provides the core functionality of Iceweasel, Debian's variant of Mozilla's browser technology.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3765

Xulrunner allows remote attackers to execute arbitrary code via vectors related to nsCSSFrameConstructor::ContentAppended, the appendChild method, incorrect index tracking, and the creation of multiple frames, which triggers memory corruption.

CVE-2010-3174

CVE-2010-3176

Multiple unspecified vulnerabilities in the browser engine in Xulrunner allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors.

CVE-2010-3177

Multiple cross-site scripting (XSS) vulnerabilities in the Gopher parser in Xulrunner allow remote attackers to inject arbitrary web script or HTML via a crafted name of a (1) file or (2) directory on a Gopher server.

CVE-2010-3178

Xulrunner does not properly handle certain modal calls made by javascript: URLs in circumstances related to opening a new window and performing cross-domain navigation, which allows remote attackers to bypass the Same Origin Policy via a crafted HTML document.

CVE-2010-3179

Stack-based buffer overflow in the text-rendering functionality in Xulrunner allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a long argument to the document.write method.

CVE-2010-3180

Use-after-free vulnerability in the nsBarProp function in Xulrunner allows remote attackers to execute arbitrary code by accessing the locationbar property of a closed window.

CVE-2010-3183

The LookupGetterOrSetter function in Xulrunner does not properly support window.__lookupGetter__ function calls that lack arguments, which allows remote attackers to execute arbitrary code or cause a denial of service (incorrect pointer dereference and application crash) via a crafted HTML document.

In addition, this security update includes corrections for regressions caused by the fixes for CVE-2010-0654 and CVE-2010-2769 in DSA-2075-1 and DSA-2106-1.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.19-6.

For the unstable distribution (sid) and the upcoming stable distribution (squeeze), these problems have been fixed in version 3.5.15-1 of the iceweasel package.

We recommend that you upgrade your Xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-6", rls:"DEB5"))) {
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
