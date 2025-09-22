# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892690");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-29374", "CVE-2021-0129", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-28688", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29155", "CVE-2021-29264", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-31829", "CVE-2021-31916", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-3483", "CVE-2021-3506", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-38208");
  script_tag(name:"creation_date", value:"2021-06-24 05:32:04 +0000 (Thu, 24 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-25 18:38:53 +0000 (Tue, 25 May 2021)");

  script_name("Debian: Security Advisory (DLA-2690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2690-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2690-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service, or information leaks.

CVE-2020-24586, CVE-2020-24587, CVE-2020-26147 Mathy Vanhoef discovered that many Wi-Fi implementations, including Linux's mac80211, did not correctly implement reassembly of fragmented packets. In some circumstances, an attacker within range of a network could exploit these flaws to forge arbitrary packets and/or to access sensitive data on that network.

CVE-2020-24588

Mathy Vanhoef discovered that most Wi-Fi implementations, including Linux's mac80211, did not authenticate the is aggregated packet header flag. An attacker within range of a network could exploit this to forge arbitrary packets on that network.

CVE-2020-25670, CVE-2020-25671, CVE-2021-23134 kiyin (Yin Liang ) of TenCent discovered several reference counting bugs in the NFC LLCP implementation which could lead to use-after-free. A local user could exploit these for denial of service (crash or memory corruption) or possibly for privilege escalation. Nadav Markus and Or Cohen of Palo Alto Networks discovered that the original fixes for these introduced a new bug that could result in use-after-free and double-free. This has also been fixed.

CVE-2020-25672

kiyin (Yin Liang ) of TenCent discovered a memory leak in the NFC LLCP implementation. A local user could exploit this for denial of service (memory exhaustion).

CVE-2020-26139

Mathy Vanhoef discovered that a bug in some Wi-Fi implementations, including Linux's mac80211. When operating in AP mode, they would forward EAPOL frames from one client to another while the sender was not yet authenticated. An attacker within range of a network could use this for denial of service or as an aid to exploiting other vulnerabilities.

CVE-2020-26558, CVE-2021-0129 Researchers at ANSSI discovered vulnerabilities in the Bluetooth Passkey authentication method, and in Linux's implementation of it. An attacker within range of two Bluetooth devices while they pair using Passkey authentication could exploit this to obtain the shared secret (Passkey) and then impersonate either of the devices to each other.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory management. A parent and child process initially share all their memory, but when either writes to a shared page, the page is duplicated and unshared (copy-on-write). However, in case an operation such as vmsplice() required the kernel to take an additional reference to a shared page, and a copy-on-write occurs during this operation, the kernel might have accessed the wrong process's memory. For some programs, this could lead to an information leak or data corruption.

CVE-2021-3483

Ma Zhe Yu (Zheyu Ma) reported a bug in the nosy driver for TI PCILynx FireWire controllers, which could lead to list corruption and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-686", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-686-pae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all-arm64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all-armel", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all-armhf", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-all-i386", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-arm64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-armmp", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-armmp-lpae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-cloud-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-common", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-common-rt", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-marvell", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-rpi", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-rt-686-pae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-rt-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-rt-arm64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.17-rt-armmp", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-686", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-686-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-686-pae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-686-pae-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-amd64-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-arm64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-arm64-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-armmp", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-armmp-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-armmp-lpae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-armmp-lpae-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-cloud-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-cloud-amd64-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-marvell", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-marvell-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rpi", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rpi-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-686-pae", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-686-pae-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-amd64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-amd64-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-arm64", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-arm64-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-armmp", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.17-rt-armmp-dbg", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.17", ver:"4.19.194-1~deb9u1", rls:"DEB9"))) {
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
