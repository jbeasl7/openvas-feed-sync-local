# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6164");
  script_cve_id("CVE-2026-3913", "CVE-2026-3914", "CVE-2026-3915", "CVE-2026-3916", "CVE-2026-3917", "CVE-2026-3918", "CVE-2026-3919", "CVE-2026-3920", "CVE-2026-3921", "CVE-2026-3922", "CVE-2026-3923", "CVE-2026-3924", "CVE-2026-3925", "CVE-2026-3926", "CVE-2026-3927", "CVE-2026-3928", "CVE-2026-3929", "CVE-2026-3930", "CVE-2026-3931", "CVE-2026-3932", "CVE-2026-3934", "CVE-2026-3935", "CVE-2026-3936", "CVE-2026-3937", "CVE-2026-3938", "CVE-2026-3939", "CVE-2026-3940", "CVE-2026-3941", "CVE-2026-3942");
  script_tag(name:"creation_date", value:"2026-03-13 04:35:16 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-16 12:45:41 +0000 (Mon, 16 Mar 2026)");

  script_name("Debian: Security Advisory (DSA-6164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6164-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6164-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-6164-1 advisory.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-headless-shell", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"146.0.7680.71-1~deb12u1", rls:"DEB12"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-headless-shell", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"146.0.7680.71-1~deb13u1", rls:"DEB13"))) {
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
