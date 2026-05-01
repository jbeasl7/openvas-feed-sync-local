# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6205");
  script_cve_id("CVE-2026-5858", "CVE-2026-5859", "CVE-2026-5860", "CVE-2026-5861", "CVE-2026-5862", "CVE-2026-5863", "CVE-2026-5864", "CVE-2026-5865", "CVE-2026-5866", "CVE-2026-5867", "CVE-2026-5868", "CVE-2026-5869", "CVE-2026-5870", "CVE-2026-5871", "CVE-2026-5872", "CVE-2026-5873", "CVE-2026-5874", "CVE-2026-5875", "CVE-2026-5876", "CVE-2026-5877", "CVE-2026-5878", "CVE-2026-5879", "CVE-2026-5880", "CVE-2026-5881", "CVE-2026-5882", "CVE-2026-5883", "CVE-2026-5884", "CVE-2026-5885", "CVE-2026-5886", "CVE-2026-5887", "CVE-2026-5888", "CVE-2026-5889", "CVE-2026-5890", "CVE-2026-5891", "CVE-2026-5892", "CVE-2026-5893", "CVE-2026-5894", "CVE-2026-5895", "CVE-2026-5896", "CVE-2026-5897", "CVE-2026-5898", "CVE-2026-5899", "CVE-2026-5900", "CVE-2026-5901", "CVE-2026-5902", "CVE-2026-5903", "CVE-2026-5904", "CVE-2026-5905", "CVE-2026-5906", "CVE-2026-5907", "CVE-2026-5908", "CVE-2026-5909", "CVE-2026-5910", "CVE-2026-5911", "CVE-2026-5912", "CVE-2026-5913", "CVE-2026-5914", "CVE-2026-5915", "CVE-2026-5918", "CVE-2026-5919");
  script_tag(name:"creation_date", value:"2026-04-13 05:04:12 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-6205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6205-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6205-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-6205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 12, Debian 13.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-headless-shell", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"147.0.7727.55-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-headless-shell", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"147.0.7727.55-1~deb13u1", rls:"DEB13"))) {
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
