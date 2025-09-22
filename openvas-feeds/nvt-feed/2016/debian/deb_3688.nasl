# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703688");
  script_cve_id("CVE-2015-4000", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7575", "CVE-2016-1938", "CVE-2016-1950", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2834");
  script_tag(name:"creation_date", value:"2016-10-04 22:00:00 +0000 (Tue, 04 Oct 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-13 15:49:48 +0000 (Mon, 13 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3688-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3688-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3688");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-3688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in NSS, the cryptography library developed by the Mozilla project.

CVE-2015-4000

David Adrian et al. reported that it may be feasible to attack Diffie-Hellman-based cipher suites in certain circumstances, compromising the confidentiality and integrity of data encrypted with Transport Layer Security (TLS).

CVE-2015-7181

CVE-2015-7182

CVE-2016-1950

Tyson Smith, David Keeler, and Francis Gabriel discovered heap-based buffer overflows in the ASN.1 DER parser, potentially leading to arbitrary code execution.

CVE-2015-7575

Karthikeyan Bhargavan discovered that TLS client implementation accepted MD5-based signatures for TLS 1.2 connections with forward secrecy, weakening the intended security strength of TLS connections.

CVE-2016-1938

Hanno Boeck discovered that NSS miscomputed the result of integer division for certain inputs. This could weaken the cryptographic protections provided by NSS. However, NSS implements RSA-CRT leak hardening, so RSA private keys are not directly disclosed by this issue.

CVE-2016-1978

Eric Rescorla discovered a use-after-free vulnerability in the implementation of ECDH-based TLS handshakes, with unknown consequences.

CVE-2016-1979

Tim Taubert discovered a use-after-free vulnerability in ASN.1 DER processing, with application-specific impact.

CVE-2016-2834

Tyson Smith and Jed Davis discovered unspecified memory-safety bugs in NSS.

In addition, the NSS library did not ignore environment variables in processes which underwent a SUID/SGID/AT_SECURE transition at process start. In certain system configurations, this allowed local users to escalate their privileges.

This update contains further correctness and stability fixes without immediate security impact.

For the stable distribution (jessie), these problems have been fixed in version 2:3.26-1+debu8u1.

For the unstable distribution (sid), these problems have been fixed in version 2:3.23-1.

We recommend that you upgrade your nss packages.");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.26-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"2:3.26-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dbg", ver:"2:3.26-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"2:3.26-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"2:3.26-1+debu8u1", rls:"DEB8"))) {
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
