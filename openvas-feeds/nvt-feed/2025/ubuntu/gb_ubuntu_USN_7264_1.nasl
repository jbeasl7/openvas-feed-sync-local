# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7264.1");
  script_cve_id("CVE-2024-12797", "CVE-2024-13176", "CVE-2024-9143");
  script_tag(name:"creation_date", value:"2025-02-12 04:04:12 +0000 (Wed, 12 Feb 2025)");
  script_version("2025-02-12T05:37:43+0000");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.10");

  script_xref(name:"Advisory-ID", value:"USN-7264-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7264-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-7264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL clients incorrectly handled authenticating
servers using RFC7250 Raw Public Keys. In certain cases, the connection
will not abort as expected, possibly causing the communication to be
intercepted. (CVE-2024-12797)

George Pantelakis and Alicja Kario discovered that OpenSSL had a timing
side-channel when performing ECDSA signature computations. A remote
attacker could possibly use this issue to recover private data.
(CVE-2024-13176)

It was discovered that OpenSSL incorrectly handled certain memory
operations when using low-level GF(2^m) elliptic curve APIs with untrusted
explicit values for the field polynomial. When being used in this uncommon
fashion, a remote attacker could use this issue to cause OpenSSL to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2024-9143)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 24.10.");

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

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.3.1-2ubuntu2.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.3.1-2ubuntu2.1", rls:"UBUNTU24.10"))) {
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
