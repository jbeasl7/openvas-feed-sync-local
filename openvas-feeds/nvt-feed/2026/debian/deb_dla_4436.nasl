# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2026.4436");
  script_cve_id("CVE-2024-47666", "CVE-2025-37899", "CVE-2025-38057", "CVE-2025-38556", "CVE-2025-38593", "CVE-2025-38678", "CVE-2025-39805", "CVE-2025-40083", "CVE-2025-40211", "CVE-2025-40214", "CVE-2025-40248", "CVE-2025-40252", "CVE-2025-40253", "CVE-2025-40254", "CVE-2025-40257", "CVE-2025-40258", "CVE-2025-40259", "CVE-2025-40261", "CVE-2025-40262", "CVE-2025-40263", "CVE-2025-40264", "CVE-2025-40269", "CVE-2025-40271", "CVE-2025-40272", "CVE-2025-40273", "CVE-2025-40275", "CVE-2025-40277", "CVE-2025-40278", "CVE-2025-40279", "CVE-2025-40280", "CVE-2025-40281", "CVE-2025-40282", "CVE-2025-40283", "CVE-2025-40284", "CVE-2025-40285", "CVE-2025-40286", "CVE-2025-40288", "CVE-2025-40292", "CVE-2025-40293", "CVE-2025-40294", "CVE-2025-40297", "CVE-2025-40301", "CVE-2025-40304", "CVE-2025-40306", "CVE-2025-40308", "CVE-2025-40309", "CVE-2025-40312", "CVE-2025-40313", "CVE-2025-40314", "CVE-2025-40315", "CVE-2025-40317", "CVE-2025-40318", "CVE-2025-40319", "CVE-2025-40321", "CVE-2025-40322", "CVE-2025-40323", "CVE-2025-40324", "CVE-2025-40331", "CVE-2025-40341", "CVE-2025-40342", "CVE-2025-40343", "CVE-2025-40345", "CVE-2025-40360", "CVE-2025-40363", "CVE-2025-68168", "CVE-2025-68171", "CVE-2025-68173", "CVE-2025-68176", "CVE-2025-68177", "CVE-2025-68185", "CVE-2025-68191", "CVE-2025-68192", "CVE-2025-68194", "CVE-2025-68200", "CVE-2025-68204", "CVE-2025-68214", "CVE-2025-68217", "CVE-2025-68218", "CVE-2025-68220", "CVE-2025-68227", "CVE-2025-68229", "CVE-2025-68231", "CVE-2025-68233", "CVE-2025-68237", "CVE-2025-68238", "CVE-2025-68241", "CVE-2025-68244", "CVE-2025-68245", "CVE-2025-68246", "CVE-2025-68282", "CVE-2025-68283", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68286", "CVE-2025-68287", "CVE-2025-68288", "CVE-2025-68289", "CVE-2025-68290", "CVE-2025-68295", "CVE-2025-68301", "CVE-2025-68302", "CVE-2025-68303", "CVE-2025-68307", "CVE-2025-68308", "CVE-2025-68310", "CVE-2025-68312", "CVE-2025-68321", "CVE-2025-68327", "CVE-2025-68328", "CVE-2025-68330", "CVE-2025-68331", "CVE-2025-68339", "CVE-2025-68343", "CVE-2025-68734");
  script_tag(name:"creation_date", value:"2026-01-14 13:45:11 +0000 (Wed, 14 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 18:00:28 +0000 (Wed, 26 Nov 2025)");

  script_name("Debian: Security Advisory (DLA-4436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4436-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2026/DLA-4436-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-6.1' package(s) announced via the DLA-4436-1 advisory.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp-lpae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-rt-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-686", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-686-pae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-amd64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-arm64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-armmp-lpae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-cloud-amd64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-cloud-arm64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-common", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-common-rt", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-rt-686-pae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-rt-amd64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-rt-arm64", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.42-rt-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-pae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-signed-template", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-signed-template", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-i386-signed-template", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-686-pae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-686-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-686-pae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-686-pae-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-686-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-amd64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-arm64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-armmp-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-armmp-lpae", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-armmp-lpae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-cloud-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-cloud-amd64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-cloud-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-cloud-arm64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-686-pae-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-686-pae-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-amd64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-amd64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-arm64-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-arm64-unsigned", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-armmp", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.42-rt-armmp-dbg", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-0.deb11.42", ver:"6.1.159-1~deb11u1", rls:"DEB11"))) {
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
