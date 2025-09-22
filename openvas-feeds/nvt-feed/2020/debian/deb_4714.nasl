# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704714");
  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456", "CVE-2020-6457", "CVE-2020-6458", "CVE-2020-6459", "CVE-2020-6460", "CVE-2020-6461", "CVE-2020-6462", "CVE-2020-6463", "CVE-2020-6464", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6492", "CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496", "CVE-2020-6497", "CVE-2020-6498", "CVE-2020-6505", "CVE-2020-6506", "CVE-2020-6507", "CVE-2020-6509", "CVE-2020-6831");
  script_tag(name:"creation_date", value:"2020-07-03 03:01:04 +0000 (Fri, 03 Jul 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 16:31:24 +0000 (Thu, 28 May 2020)");

  script_name("Debian: Security Advisory (DSA-4714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4714-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4714-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4714");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2020-6423

A use-after-free issue was found in the audio implementation.

CVE-2020-6430

Avihay Cohen discovered a type confusion issue in the v8 javascript library.

CVE-2020-6431

Luan Herrera discovered a policy enforcement error.

CVE-2020-6432

Luan Herrera discovered a policy enforcement error.

CVE-2020-6433

Luan Herrera discovered a policy enforcement error in extensions.

CVE-2020-6434

HyungSeok Han discovered a use-after-free issue in the developer tools.

CVE-2020-6435

Sergei Glazunov discovered a policy enforcement error in extensions.

CVE-2020-6436

Igor Bukanov discovered a use-after-free issue.

CVE-2020-6437

Jann Horn discovered an implementation error in WebView.

CVE-2020-6438

Ng Yik Phang discovered a policy enforcement error in extensions.

CVE-2020-6439

remkoboonstra discovered a policy enforcement error.

CVE-2020-6440

David Erceg discovered an implementation error in extensions.

CVE-2020-6441

David Erceg discovered a policy enforcement error.

CVE-2020-6442

B@rMey discovered an implementation error in the page cache.

CVE-2020-6443

@lovasoa discovered an implementation error in the developer tools.

CVE-2020-6444

mlfbrown discovered an uninitialized variable in the WebRTC implementation.

CVE-2020-6445

Jun Kokatsu discovered a policy enforcement error.

CVE-2020-6446

Jun Kokatsu discovered a policy enforcement error.

CVE-2020-6447

David Erceg discovered an implementation error in the developer tools.

CVE-2020-6448

Guang Gong discovered a use-after-free issue in the v8 javascript library.

CVE-2020-6454

Leecraso and Guang Gong discovered a use-after-free issue in extensions.

CVE-2020-6455

Nan Wang and Guang Gong discovered an out-of-bounds read issue in the WebSQL implementation.

CVE-2020-6456

Michal Bentkowski discovered insufficient validation of untrusted input.

CVE-2020-6457

Leecraso and Guang Gong discovered a use-after-free issue in the speech recognizer.

CVE-2020-6458

Aleksandar Nikolic discovered an out-of-bounds read and write issue in the pdfium library.

CVE-2020-6459

Zhe Jin discovered a use-after-free issue in the payments implementation.

CVE-2020-6460

It was discovered that URL formatting was insufficiently validated.

CVE-2020-6461

Zhe Jin discovered a use-after-free issue.

CVE-2020-6462

Zhe Jin discovered a use-after-free issue in task scheduling.

CVE-2020-6463

Pawel Wylecial discovered a use-after-free issue in the ANGLE library.

CVE-2020-6464

Looben Yang discovered a type confusion issue in Blink/Webkit.

CVE-2020-6465

Woojin Oh discovered a use-after-free issue.

CVE-2020-6466

Zhe Jin discovered a use-after-free issue.

CVE-2020-6467

ZhanJia Song discovered a use-after-free issue in the WebRTC implementation.

CVE-2020-6468

Chris Salls and Jake Corina discovered a type confusion issue in the v8 javascript ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
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
