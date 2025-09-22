# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704645");
  script_cve_id("CVE-2019-20503", "CVE-2020-6422", "CVE-2020-6424", "CVE-2020-6425", "CVE-2020-6426", "CVE-2020-6427", "CVE-2020-6428", "CVE-2020-6429", "CVE-2020-6449");
  script_tag(name:"creation_date", value:"2020-03-24 04:00:17 +0000 (Tue, 24 Mar 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 16:08:51 +0000 (Tue, 24 Mar 2020)");

  script_name("Debian: Security Advisory (DSA-4645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4645-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4645-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4645");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-20503

Natalie Silvanovich discovered an out-of-bounds read issue in the usrsctp library.

CVE-2020-6422

David Manouchehri discovered a use-after-free issue in the WebGL implementation.

CVE-2020-6424

Sergei Glazunov discovered a use-after-free issue.

CVE-2020-6425

Sergei Glazunov discovered a policy enforcement error related to extensions.

CVE-2020-6426

Avihay Cohen discovered an implementation error in the v8 javascript library.

CVE-2020-6427

Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6428

Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6429

Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6449

Man Yue Mo discovered a use-after-free issue in the audio implementation.

For the oldstable distribution (stretch), security support for chromium has been discontinued.

For the stable distribution (buster), these problems have been fixed in version 80.0.3987.149-1~deb10u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
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
