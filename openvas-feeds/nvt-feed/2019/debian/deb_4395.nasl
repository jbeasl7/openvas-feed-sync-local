# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704395");
  script_cve_id("CVE-2018-17481", "CVE-2018-20073", "CVE-2019-13684", "CVE-2019-13768", "CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5782", "CVE-2019-5783", "CVE-2019-5784");
  script_tag(name:"creation_date", value:"2019-02-17 23:00:00 +0000 (Sun, 17 Feb 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-19 20:19:35 +0000 (Tue, 19 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-4395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4395-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4395-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4395");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4395-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-17481

A use-after-free issue was discovered in the pdfium library.

CVE-2019-5754

Klzgrad discovered an error in the QUIC networking implementation.

CVE-2019-5755

Jay Bosamiya discovered an implementation error in the v8 javascript library.

CVE-2019-5756

A use-after-free issue was discovered in the pdfium library.

CVE-2019-5757

Alexandru Pitis discovered a type confusion error in the SVG image format implementation.

CVE-2019-5758

Zhe Jin discovered a use-after-free issue in blink/webkit.

CVE-2019-5759

Almog Benin discovered a use-after-free issue when handling HTML pages containing select elements.

CVE-2019-5760

Zhe Jin discovered a use-after-free issue in the WebRTC implementation.

CVE-2019-5762

A use-after-free issue was discovered in the pdfium library.

CVE-2019-5763

Guang Gon discovered an input validation error in the v8 javascript library.

CVE-2019-5764

Eyal Itkin discovered a use-after-free issue in the WebRTC implementation.

CVE-2019-5765

Sergey Toshin discovered a policy enforcement error.

CVE-2019-5766

David Erceg discovered a policy enforcement error.

CVE-2019-5767

Haoran Lu, Yifan Zhang, Luyi Xing, and Xiaojing Liao reported an error in the WebAPKs user interface.

CVE-2019-5768

Rob Wu discovered a policy enforcement error in the developer tools.

CVE-2019-5769

Guy Eshel discovered an input validation error in blink/webkit.

CVE-2019-5770

hemidallt discovered a buffer overflow issue in the WebGL implementation.

CVE-2019-5772

Zhen Zhou discovered a use-after-free issue in the pdfium library.

CVE-2019-5773

Yongke Wong discovered an input validation error in the IndexDB implementation.

CVE-2019-5774

Junghwan Kang and Juno Im discovered an input validation error in the SafeBrowsing implementation.

CVE-2019-5775

evil1m0 discovered a policy enforcement error.

CVE-2019-5776

Lnyas Zhang discovered a policy enforcement error.

CVE-2019-5777

Khalil Zhani discovered a policy enforcement error.

CVE-2019-5778

David Erceg discovered a policy enforcement error in the Extensions implementation.

CVE-2019-5779

David Erceg discovered a policy enforcement error in the ServiceWorker implementation.

CVE-2019-5780

Andreas Hegenberg discovered a policy enforcement error.

CVE-2019-5781

evil1m0 discovered a policy enforcement error.

CVE-2019-5782

Qixun Zhao discovered an implementation error in the v8 javascript library.

CVE-2019-5783

Shintaro Kobori discovered an input validation error in the developer tools.

CVE-2019-5784

Lucas Pinheiro discovered an implementation error in the v8 javascript library.

For the stable distribution (stretch), these problems have been fixed in version 72.0.3626.96-1~deb9u1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9"))) {
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
