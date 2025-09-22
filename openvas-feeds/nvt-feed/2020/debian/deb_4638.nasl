# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704638");
  script_cve_id("CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19925", "CVE-2019-19926", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6385", "CVE-2020-6386", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6418", "CVE-2020-6420", "CVE-2020-6499", "CVE-2020-6500", "CVE-2020-6501", "CVE-2020-6502");
  script_tag(name:"creation_date", value:"2020-03-18 10:45:59 +0000 (Wed, 18 Mar 2020)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:05:12 +0000 (Tue, 24 Mar 2020)");

  script_name("Debian: Security Advisory (DSA-4638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4638-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4638-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4638");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-19880

Richard Lorenz discovered an issue in the sqlite library.

CVE-2019-19923

Richard Lorenz discovered an out-of-bounds read issue in the sqlite library.

CVE-2019-19925

Richard Lorenz discovered an issue in the sqlite library.

CVE-2019-19926

Richard Lorenz discovered an implementation error in the sqlite library.

CVE-2020-6381

UK's National Cyber Security Centre discovered an integer overflow issue in the v8 javascript library.

CVE-2020-6382

Soyeon Park and Wen Xu discovered a type error in the v8 javascript library.

CVE-2020-6383

Sergei Glazunov discovered a type error in the v8 javascript library.

CVE-2020-6384

David Manoucheri discovered a use-after-free issue in WebAudio.

CVE-2020-6385

Sergei Glazunov discovered a policy enforcement error.

CVE-2020-6386

Zhe Jin discovered a use-after-free issue in speech processing.

CVE-2020-6387

Natalie Silvanovich discovered an out-of-bounds write error in the WebRTC implementation.

CVE-2020-6388

Sergei Glazunov discovered an out-of-bounds read error in the WebRTC implementation.

CVE-2020-6389

Natalie Silvanovich discovered an out-of-bounds write error in the WebRTC implementation.

CVE-2020-6390

Sergei Glazunov discovered an out-of-bounds read error.

CVE-2020-6391

Michal Bentkowski discoverd that untrusted input was insufficiently validated.

CVE-2020-6392

The Microsoft Edge Team discovered a policy enforcement error.

CVE-2020-6393

Mark Amery discovered a policy enforcement error.

CVE-2020-6394

Phil Freo discovered a policy enforcement error.

CVE-2020-6395

Pierre Langlois discovered an out-of-bounds read error in the v8 javascript library.

CVE-2020-6396

William Luc Ritchie discovered an error in the skia library.

CVE-2020-6397

Khalil Zhani discovered a user interface error.

CVE-2020-6398

pdknsk discovered an uninitialized variable in the pdfium library.

CVE-2020-6399

Luan Herrera discovered a policy enforcement error.

CVE-2020-6400

Takashi Yoneuchi discovered an error in Cross-Origin Resource Sharing.

CVE-2020-6401

Tzachy Horesh discovered that user input was insufficiently validated.

CVE-2020-6402

Vladimir Metnew discovered a policy enforcement error.

CVE-2020-6403

Khalil Zhani discovered a user interface error.

CVE-2020-6404

kanchi discovered an error in Blink/Webkit.

CVE-2020-6405

Yongheng Chen and Rui Zhong discovered an out-of-bounds read issue in the sqlite library.

CVE-2020-6406

Sergei Glazunov discovered a use-after-free issue.

CVE-2020-6407

Sergei Glazunov discovered an out-of-bounds read error.

CVE-2020-6408

Zhong Zhaochen discovered a policy enforcement error in Cross-Origin Resource Sharing.

CVE-2020-6409

Divagar S and Bharathi V discovered an error in the omnibox implementation.

CVE-2020-6410

evil1m0 discovered a policy enforcement error.

CVE-2020-6411

Khalil Zhani ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"80.0.3987.132-1~deb10u1", rls:"DEB10"))) {
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
