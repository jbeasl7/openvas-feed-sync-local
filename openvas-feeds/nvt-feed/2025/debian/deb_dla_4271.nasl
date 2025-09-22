# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4271");
  script_cve_id("CVE-2024-26618", "CVE-2024-26783", "CVE-2024-26807", "CVE-2024-28956", "CVE-2024-35790", "CVE-2024-36903", "CVE-2024-36927", "CVE-2024-43840", "CVE-2024-46751", "CVE-2024-53203", "CVE-2024-53209", "CVE-2024-57945", "CVE-2025-21645", "CVE-2025-21839", "CVE-2025-21931", "CVE-2025-22062", "CVE-2025-37819", "CVE-2025-37890", "CVE-2025-37897", "CVE-2025-37901", "CVE-2025-37903", "CVE-2025-37905", "CVE-2025-37909", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37917", "CVE-2025-37921", "CVE-2025-37923", "CVE-2025-37924", "CVE-2025-37927", "CVE-2025-37928", "CVE-2025-37929", "CVE-2025-37930", "CVE-2025-37932", "CVE-2025-37936", "CVE-2025-37947", "CVE-2025-37948", "CVE-2025-37949", "CVE-2025-37951", "CVE-2025-37953", "CVE-2025-37959", "CVE-2025-37961", "CVE-2025-37962", "CVE-2025-37963", "CVE-2025-37964", "CVE-2025-37967", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37972", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-37992", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37997", "CVE-2025-37998", "CVE-2025-38005", "CVE-2025-38007", "CVE-2025-38009", "CVE-2025-38015", "CVE-2025-38018", "CVE-2025-38020", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38027", "CVE-2025-38094", "CVE-2025-38095", "CVE-2025-38177");
  script_tag(name:"creation_date", value:"2025-08-13 04:11:32 +0000 (Wed, 13 Aug 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-16 16:46:17 +0000 (Thu, 16 Jan 2025)");

  script_name("Debian: Security Advisory (DLA-4271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4271-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4271-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-6.1' package(s) announced via the DLA-4271-1 advisory.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp-lpae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-rt-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-686", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-686-pae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-amd64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-arm64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-armmp-lpae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-cloud-amd64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-cloud-arm64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-common", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-common-rt", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-rt-686-pae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-rt-amd64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-rt-arm64", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.37-rt-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-pae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-signed-template", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-signed-template", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-i386-signed-template", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-686-pae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-686-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-686-pae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-686-pae-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-686-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-amd64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-arm64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-armmp-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-armmp-lpae", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-armmp-lpae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-cloud-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-cloud-amd64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-cloud-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-cloud-arm64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-686-pae-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-686-pae-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-amd64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-amd64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-arm64-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-arm64-unsigned", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-armmp", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.37-rt-armmp-dbg", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-0.deb11.37", ver:"6.1.140-1~deb11u1", rls:"DEB11"))) {
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
