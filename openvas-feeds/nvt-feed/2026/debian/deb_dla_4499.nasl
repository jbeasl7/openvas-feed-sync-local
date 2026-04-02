# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2026.4499");
  script_cve_id("CVE-2023-53424", "CVE-2024-26822", "CVE-2024-57895", "CVE-2025-22026", "CVE-2025-23155", "CVE-2025-37786", "CVE-2025-37822", "CVE-2025-37920", "CVE-2025-38201", "CVE-2025-38643", "CVE-2025-39763", "CVE-2025-40082", "CVE-2025-40251", "CVE-2025-68358", "CVE-2025-71089", "CVE-2025-71144", "CVE-2025-71220", "CVE-2025-71222", "CVE-2025-71224", "CVE-2025-71232", "CVE-2025-71233", "CVE-2025-71235", "CVE-2025-71236", "CVE-2025-71237", "CVE-2025-71238", "CVE-2026-23111", "CVE-2026-23112", "CVE-2026-23169", "CVE-2026-23176", "CVE-2026-23178", "CVE-2026-23180", "CVE-2026-23182", "CVE-2026-23187", "CVE-2026-23190", "CVE-2026-23193", "CVE-2026-23198", "CVE-2026-23202", "CVE-2026-23205", "CVE-2026-23206", "CVE-2026-23209", "CVE-2026-23216", "CVE-2026-23220", "CVE-2026-23221", "CVE-2026-23222", "CVE-2026-23228", "CVE-2026-23229", "CVE-2026-23230", "CVE-2026-23234", "CVE-2026-23235", "CVE-2026-23236", "CVE-2026-23237", "CVE-2026-23238");
  script_tag(name:"creation_date", value:"2026-03-16 04:54:20 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-19 19:20:45 +0000 (Thu, 19 Mar 2026)");

  script_name("Debian: Security Advisory (DLA-4499-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4499-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2026/DLA-4499-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-6.1' package(s) announced via the DLA-4499-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'linux-6.1' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp-lpae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-rt-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-686", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-686-pae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-amd64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-arm64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-armmp-lpae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-cloud-amd64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-cloud-arm64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-common", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-common-rt", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-rt-686-pae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-rt-amd64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-rt-arm64", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.44-rt-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-pae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-signed-template", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-signed-template", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-i386-signed-template", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-686-pae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-686-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-686-pae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-686-pae-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-686-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-amd64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-arm64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-armmp-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-armmp-lpae", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-armmp-lpae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-cloud-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-cloud-amd64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-cloud-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-cloud-arm64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-686-pae-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-686-pae-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-amd64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-amd64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-arm64-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-arm64-unsigned", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-armmp", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.44-rt-armmp-dbg", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-0.deb11.44", ver:"6.1.164-1~deb11u1", rls:"DEB11"))) {
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
