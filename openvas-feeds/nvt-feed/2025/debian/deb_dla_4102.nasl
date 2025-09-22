# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4102");
  script_cve_id("CVE-2024-26596", "CVE-2024-40945", "CVE-2024-42069", "CVE-2024-42122", "CVE-2024-45001", "CVE-2024-47726", "CVE-2024-49989", "CVE-2024-50061", "CVE-2024-54458", "CVE-2024-56549", "CVE-2024-57834", "CVE-2024-57973", "CVE-2024-57978", "CVE-2024-57979", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-57986", "CVE-2024-57993", "CVE-2024-57996", "CVE-2024-57997", "CVE-2024-57998", "CVE-2024-58001", "CVE-2024-58007", "CVE-2024-58009", "CVE-2024-58010", "CVE-2024-58011", "CVE-2024-58013", "CVE-2024-58014", "CVE-2024-58016", "CVE-2024-58017", "CVE-2024-58020", "CVE-2024-58034", "CVE-2024-58051", "CVE-2024-58052", "CVE-2024-58054", "CVE-2024-58055", "CVE-2024-58056", "CVE-2024-58058", "CVE-2024-58061", "CVE-2024-58063", "CVE-2024-58068", "CVE-2024-58069", "CVE-2024-58071", "CVE-2024-58072", "CVE-2024-58076", "CVE-2024-58077", "CVE-2024-58080", "CVE-2024-58083", "CVE-2024-58085", "CVE-2024-58086", "CVE-2025-21684", "CVE-2025-21700", "CVE-2025-21701", "CVE-2025-21703", "CVE-2025-21704", "CVE-2025-21705", "CVE-2025-21706", "CVE-2025-21707", "CVE-2025-21708", "CVE-2025-21711", "CVE-2025-21715", "CVE-2025-21716", "CVE-2025-21718", "CVE-2025-21719", "CVE-2025-21722", "CVE-2025-21724", "CVE-2025-21725", "CVE-2025-21726", "CVE-2025-21727", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21734", "CVE-2025-21735", "CVE-2025-21736", "CVE-2025-21738", "CVE-2025-21744", "CVE-2025-21745", "CVE-2025-21748", "CVE-2025-21749", "CVE-2025-21750", "CVE-2025-21753", "CVE-2025-21758", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-21767", "CVE-2025-21772", "CVE-2025-21775", "CVE-2025-21776", "CVE-2025-21779", "CVE-2025-21780", "CVE-2025-21781", "CVE-2025-21782", "CVE-2025-21785", "CVE-2025-21787", "CVE-2025-21790", "CVE-2025-21791", "CVE-2025-21792", "CVE-2025-21794", "CVE-2025-21795", "CVE-2025-21796", "CVE-2025-21799", "CVE-2025-21802", "CVE-2025-21804", "CVE-2025-21806", "CVE-2025-21811", "CVE-2025-21812", "CVE-2025-21814", "CVE-2025-21819", "CVE-2025-21820", "CVE-2025-21821", "CVE-2025-21823", "CVE-2025-21826", "CVE-2025-21829", "CVE-2025-21830", "CVE-2025-21832", "CVE-2025-21835");
  script_tag(name:"creation_date", value:"2025-04-01 04:06:22 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:53:49 +0000 (Thu, 13 Mar 2025)");

  script_name("Debian: Security Advisory (DLA-4102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4102-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4102-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-6.1' package(s) announced via the DLA-4102-1 advisory.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp-lpae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-rt-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-686", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-686-pae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-amd64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-arm64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-armmp-lpae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-cloud-amd64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-cloud-arm64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-common", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-common-rt", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-rt-686-pae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-rt-amd64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-rt-arm64", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.32-rt-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-pae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-signed-template", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-signed-template", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-i386-signed-template", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-686-pae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-686-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-686-pae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-686-pae-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-686-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-amd64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-arm64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-armmp-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-armmp-lpae", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-armmp-lpae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-cloud-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-cloud-amd64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-cloud-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-cloud-arm64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-686-pae-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-686-pae-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-amd64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-amd64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-arm64-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-arm64-unsigned", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-armmp", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.32-rt-armmp-dbg", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-0.deb11.32", ver:"6.1.129-1~deb11u1", rls:"DEB11"))) {
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
