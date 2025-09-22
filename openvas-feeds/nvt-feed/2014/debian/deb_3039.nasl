# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703039");
  script_cve_id("CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167", "CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177", "CVE-2014-3178", "CVE-2014-3179");
  script_tag(name:"creation_date", value:"2014-10-01 11:28:59 +0000 (Wed, 01 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3039-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3039-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3039-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3039");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3039-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2014-3160

Christian Schneider discovered a same origin bypass issue in SVG file resource fetching.

CVE-2014-3162

The Google Chrome development team addressed multiple issues with potential security impact for chromium 36.0.1985.125.

CVE-2014-3165

Colin Payne discovered a use-after-free issue in the Web Sockets implementation.

CVE-2014-3166

Antoine Delignat-Lavaud discovered an information leak in the SPDY protocol implementation.

CVE-2014-3167

The Google Chrome development team addressed multiple issues with potential security impact for chromium 36.0.1985.143.

CVE-2014-3168

cloudfuzzer discovered a use-after-free issue in SVG image file handling.

CVE-2014-3169

Andrzej Dyjak discovered a use-after-free issue in the Webkit/Blink Document Object Model implementation.

CVE-2014-3170

Rob Wu discovered a way to spoof the url of chromium extensions.

CVE-2014-3171

cloudfuzzer discovered a use-after-free issue in chromium's v8 bindings.

CVE-2014-3172

Eli Grey discovered a way to bypass access restrictions using chromium's Debugger extension API.

CVE-2014-3173

jmuizelaar discovered an uninitialized read issue in WebGL.

CVE-2014-3174

Atte Kettunen discovered an uninitialized read issue in Web Audio.

CVE-2014-3175

The Google Chrome development team addressed multiple issues with potential security impact for chromium 37.0.2062.94.

CVE-2014-3176

lokihardt@asrt discovered a combination of flaws that can lead to remote code execution outside of chromium's sandbox.

CVE-2014-3177

lokihardt@asrt discovered a combination of flaws that can lead to remote code execution outside of chromium's sandbox.

CVE-2014-3178

miaubiz discovered a use-after-free issue in the Document Object Model implementation in Blink/Webkit.

CVE-2014-3179

The Google Chrome development team addressed multiple issues with potential security impact for chromium 37.0.2062.120.

For the stable distribution (wheezy), these problems have been fixed in version 37.0.2062.120-1~deb7u1.

For the testing (jessie) and unstable (sid) distributions, these problems have been fixed in version 37.0.2062.120-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"37.0.2062.120-1~deb7u1", rls:"DEB7"))) {
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
