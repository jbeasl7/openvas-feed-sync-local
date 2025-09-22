# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704421");
  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5802", "CVE-2019-5803", "CVE-2019-5844", "CVE-2019-5845", "CVE-2019-5846");
  script_tag(name:"creation_date", value:"2019-04-06 02:00:31 +0000 (Sat, 06 Apr 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-28 17:41:56 +0000 (Tue, 28 May 2019)");

  script_name("Debian: Security Advisory (DSA-4421-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4421-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4421-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4421");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4421-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-5787

Zhe Jin discovered a use-after-free issue.

CVE-2019-5788

Mark Brand discovered a use-after-free issue in the FileAPI implementation.

CVE-2019-5789

Mark Brand discovered a use-after-free issue in the WebMIDI implementation.

CVE-2019-5790

Dimitri Fourny discovered a buffer overflow issue in the v8 javascript library.

CVE-2019-5791

Choongwoo Han discovered a type confusion issue in the v8 javascript library.

CVE-2019-5792

pdknsk discovered an integer overflow issue in the pdfium library.

CVE-2019-5793

Jun Kokatsu discovered a permissions issue in the Extensions implementation.

CVE-2019-5794

Juno Im of Theori discovered a user interface spoofing issue.

CVE-2019-5795

pdknsk discovered an integer overflow issue in the pdfium library.

CVE-2019-5796

Mark Brand discovered a race condition in the Extensions implementation.

CVE-2019-5797

Mark Brand discovered a race condition in the DOMStorage implementation.

CVE-2019-5798

Tran Tien Hung discovered an out-of-bounds read issue in the skia library.

CVE-2019-5799

sohalt discovered a way to bypass the Content Security Policy.

CVE-2019-5800

Jun Kokatsu discovered a way to bypass the Content Security Policy.

CVE-2019-5802

Ronni Skansing discovered a user interface spoofing issue.

CVE-2019-5803

Andrew Comminos discovered a way to bypass the Content Security Policy.

For the stable distribution (stretch), these problems have been fixed in version 73.0.3683.75-1~deb9u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"73.0.3683.75-1~deb9u1", rls:"DEB9"))) {
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
