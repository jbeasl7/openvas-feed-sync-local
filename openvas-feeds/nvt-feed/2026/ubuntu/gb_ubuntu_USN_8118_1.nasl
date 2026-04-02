# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8118.1");
  script_cve_id("CVE-2020-25791", "CVE-2020-25792", "CVE-2020-25793", "CVE-2020-25794", "CVE-2020-25796");
  script_tag(name:"creation_date", value:"2026-03-24 04:37:32 +0000 (Tue, 24 Mar 2026)");
  script_version("2026-03-24T05:57:14+0000");
  script_tag(name:"last_modification", value:"2026-03-24 05:57:14 +0000 (Tue, 24 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-25 19:13:11 +0000 (Fri, 25 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-8118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-8118-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8118-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-sized-chunks' package(s) announced via the USN-8118-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yechan Bae discovered that sized-chunks did not properly validate array
size when constructing Chunk. An attacker could possibly use these
issues to cause out-of-bounds access, leading to memory corruption or
undefined behavior. (CVE-2020-25791, CVE-2020-25792, CVE-2020-25793)

Yechan Bae discovered that sized-chunks had a memory safety issue in the
clone implementation when a panic occurs. An attacker could possibly use
this issue to cause improper memory handling, leading to memory
corruption or a denial of service. (CVE-2020-25794)

Yechan Bae discovered that sized-chunks could create unaligned
references in the InlineArray implementation for types with strict
alignment requirements. An attacker could possibly use this issue to
cause undefined behavior, leading to memory corruption or a denial of
service. (CVE-2020-25796)");

  script_tag(name:"affected", value:"'rust-sized-chunks' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"librust-sized-chunks-dev", ver:"0.3.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
