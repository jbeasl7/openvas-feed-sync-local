# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704701");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"creation_date", value:"2020-06-12 03:00:45 +0000 (Fri, 12 Jun 2020)");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 16:52:27 +0000 (Tue, 25 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-4701-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4701-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4701-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4701");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00320.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00329.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/intel-microcode");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'intel-microcode' package(s) announced via the DSA-4701-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update ships updated CPU microcode for some types of Intel CPUs and provides mitigations for the Special Register Buffer Data Sampling (CVE-2020-0543), Vector Register Sampling (CVE-2020-0548) and L1D Eviction Sampling (CVE-2020-0549) hardware vulnerabilities.

The microcode update for HEDT and Xeon CPUs with signature 0x50654 which was reverted in DSA 4565-2 is now included again with a fixed release.

The upstream update for Skylake-U/Y (signature 0x406e3) had to be excluded from this update due to reported hangs on boot.

For details refer to [link moved to references] [link moved to references]

For the oldstable distribution (stretch), these problems have been fixed in version 3.20200609.2~deb9u1.

For the stable distribution (buster), these problems have been fixed in version 3.20200609.2~deb10u1.

We recommend that you upgrade your intel-microcode packages.

For the detailed security status of intel-microcode please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.2~deb9u1", rls:"DEB9"))) {
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
