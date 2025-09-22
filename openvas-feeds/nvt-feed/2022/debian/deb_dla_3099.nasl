# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893099");
  script_cve_id("CVE-2020-13253", "CVE-2020-15469", "CVE-2020-15859", "CVE-2020-25084", "CVE-2020-25085", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27617", "CVE-2020-27821", "CVE-2020-28916", "CVE-2020-29129", "CVE-2020-29443", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-20181", "CVE-2021-20196", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-20257", "CVE-2021-3392", "CVE-2021-3416", "CVE-2021-3507", "CVE-2021-3527", "CVE-2021-3582", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3682", "CVE-2021-3713", "CVE-2021-3748", "CVE-2021-3930", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-26354", "CVE-2022-35414");
  script_tag(name:"creation_date", value:"2022-09-06 01:00:36 +0000 (Tue, 06 Sep 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 15:16:38 +0000 (Tue, 03 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3099-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3099-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3099-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qemu");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-3099-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2020-13253

Description

CVE-2020-15469

Description

CVE-2020-15859

Description

CVE-2020-25084

Description

CVE-2020-25085

Description

CVE-2020-25624

Description

CVE-2020-25625

Description

CVE-2020-25723

Description

CVE-2020-27617

Description

CVE-2020-27821

Description

CVE-2020-28916

Description

CVE-2020-29129

Description

CVE-2020-29443

Description

CVE-2020-35504

Description

CVE-2020-35505

Description

CVE-2021-3392

Description

CVE-2021-3416

Description

CVE-2021-3507

Description

CVE-2021-3527

Description

CVE-2021-3582

Description

CVE-2021-3607

Description

CVE-2021-3608

Description

CVE-2021-3682

Description

CVE-2021-3713

Description

CVE-2021-3748

Description

CVE-2021-3930

Description

CVE-2021-4206

Description

CVE-2021-4207

Description

CVE-2021-20181

Description

CVE-2021-20196

Description

CVE-2021-20203

Description

CVE-2021-20221

Description

CVE-2021-20257

Description

CVE-2022-26354

Description

CVE-2022-35414

Description

For Debian 10 buster, these problems have been fixed in version 1:3.1+dfsg-8+deb10u9.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
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
