# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69324");
  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0059");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2187-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2187-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2187");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Icedove, an unbranded version of the Thunderbird mail/news client.

CVE-2010-1585

Roberto Suggi Liverani discovered that the sanitising performed by ParanoidFragmentSink was incomplete.

CVE-2011-0051

Zach Hoffmann discovered that incorrect parsing of recursive eval() calls could lead to attackers forcing acceptance of a confirmation dialogue.

CVE-2011-0053

Crashes in the layout engine may lead to the execution of arbitrary code.

CVE-2011-0054, CVE-2010-0056 Christian Holler discovered buffer overflows in the Javascript engine, which could allow the execution of arbitrary code.

CVE-2011-0055

regenrecht and Igor Bukanov discovered a use-after-free error in the JSON-Implementation, which could lead to the execution of arbitrary code.

CVE-2011-0057

Daniel Kozlowski discovered that incorrect memory handling the web workers implementation could lead to the execution of arbitrary code.

CVE-2011-0059

Peleus Uhley discovered a cross-site request forgery risk in the plugin code.

As indicated in the Lenny (oldstable) release notes, security support for the Icedove packages in the oldstable needed to be stopped before the end of the regular Lenny security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a different mail client.

For the stable distribution (squeeze), this problem has been fixed in version 3.0.11-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 3.0.11-2.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze1", rls:"DEB6"))) {
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
