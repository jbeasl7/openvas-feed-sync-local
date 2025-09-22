# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704031");
  script_cve_id("CVE-2017-0898", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033");
  script_tag(name:"creation_date", value:"2017-11-10 23:00:00 +0000 (Fri, 10 Nov 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 17:35:35 +0000 (Fri, 03 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-4031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4031-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4031-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4031");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.3' package(s) announced via the DSA-4031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2017-0898

aerodudrizzt reported a buffer underrun vulnerability in the sprintf method of the Kernel module resulting in heap memory corruption or information disclosure from the heap.

CVE-2017-0903

Max Justicz reported that RubyGems is prone to an unsafe object deserialization vulnerability. When parsed by an application which processes gems, a specially crafted YAML formatted gem specification can lead to remote code execution.

CVE-2017-10784

Yusuke Endoh discovered an escape sequence injection vulnerability in the Basic authentication of WEBrick. An attacker can take advantage of this flaw to inject malicious escape sequences to the WEBrick log and potentially execute control characters on the victim's terminal emulator when reading logs.

CVE-2017-14033

asac reported a buffer underrun vulnerability in the OpenSSL extension. A remote attacker can take advantage of this flaw to cause the Ruby interpreter to crash leading to a denial of service.

For the stable distribution (stretch), these problems have been fixed in version 2.3.3-1+deb9u2.

We recommend that you upgrade your ruby2.3 packages.");

  script_tag(name:"affected", value:"'ruby2.3' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u2", rls:"DEB9"))) {
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
