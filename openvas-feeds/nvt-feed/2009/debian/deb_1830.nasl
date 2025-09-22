# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64417");
  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1307", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841", "CVE-2009-2061", "CVE-2009-2210");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1830-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1830-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1830");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird mail client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0040

The execution of arbitrary code might be possible via a crafted PNG file that triggers a free of an uninitialized pointer in (1) the png_read_png function, (2) pCAL chunk handling, or (3) setup of 16-bit gamma tables. (MFSA 2009-10)

CVE-2009-0352

It is possible to execute arbitrary code via vectors related to the layout engine. (MFSA 2009-01)

CVE-2009-0353

It is possible to execute arbitrary code via vectors related to the JavaScript engine. (MFSA 2009-01)

CVE-2009-0652

Bjoern Hoehrmann and Moxie Marlinspike discovered a possible spoofing attack via Unicode box drawing characters in internationalized domain names. (MFSA 2009-15)

CVE-2009-0771

Memory corruption and assertion failures have been discovered in the layout engine, leading to the possible execution of arbitrary code. (MFSA 2009-07)

CVE-2009-0772

The layout engine allows the execution of arbitrary code in vectors related to nsCSSStyleSheet::GetOwnerNode, events, and garbage collection. (MFSA 2009-07)

CVE-2009-0773

The JavaScript engine is prone to the execution of arbitrary code via several vectors. (MFSA 2009-07)

CVE-2009-0774

The layout engine allows the execution of arbitrary code via vectors related to gczeal. (MFSA 2009-07)

CVE-2009-0776

Georgi Guninski discovered that it is possible to obtain xml data via an issue related to the nsIRDFService. (MFSA 2009-09)

CVE-2009-1302

The browser engine is prone to a possible memory corruption via several vectors. (MFSA 2009-14)

CVE-2009-1303

The browser engine is prone to a possible memory corruption via the nsSVGElement::BindToTree function. (MFSA 2009-14)

CVE-2009-1307

Gregory Fleischer discovered that it is possible to bypass the Same Origin Policy when opening a Flash file via the view-source: scheme. (MFSA 2009-17)

CVE-2009-1832

The possible arbitrary execution of code was discovered via vectors involving 'double frame construction.' (MFSA 2009-24)

CVE-2009-1392

Several issues were discovered in the browser engine as used by icedove, which could lead to the possible execution of arbitrary code. (MFSA 2009-24)

CVE-2009-1836

Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang reported a potential man-in-the-middle attack, when using a proxy due to insufficient checks on a certain proxy response. (MFSA 2009-27)

CVE-2009-1838

moz_bug_r_a4 discovered that it is possible to execute arbitrary JavaScript with chrome privileges due to an error in the garbage collection implementation. (MFSA 2009-29)

CVE-2009-1841

moz_bug_r_a4 reported that it is possible for scripts from page content to run with elevated privileges and thus potentially executing arbitrary code with the object's chrome privileges. (MFSA ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"2.0.0.22-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"2.0.0.22-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"2.0.0.22-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"2.0.0.22-0lenny1", rls:"DEB5"))) {
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
