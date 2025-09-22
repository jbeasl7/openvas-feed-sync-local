# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891899");
  script_cve_id("CVE-2018-19502", "CVE-2018-20196", "CVE-2018-20199", "CVE-2018-20360", "CVE-2019-15296", "CVE-2019-6956");
  script_tag(name:"creation_date", value:"2019-08-29 02:00:11 +0000 (Thu, 29 Aug 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-29 16:43:49 +0000 (Thu, 29 Aug 2019)");

  script_name("Debian: Security Advisory (DLA-1899-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1899-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1899-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'faad2' package(s) announced via the DLA-1899-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in faad2, the Freeware Advanced Audio Coder:

CVE-2018-19502

Heap buffer overflow in the function excluded_channels (libfaad/syntax.c). This vulnerability might allow remote attackers to cause denial of service via crafted MPEG AAC data.

CVE-2018-20196

Stack buffer overflow in the function calculate_gain (libfaad/br_hfadj.c). This vulnerability might allow remote attackers to cause denial of service or any unspecified impact via crafted MPEG AAC data.

CVE-2018-20199, CVE-2018-20360 NULL pointer dereference in the function ifilter_bank (libfaad/filtbank.c). This vulnerability might allow remote attackers to cause denial of service via crafted MPEG AAC data.

CVE-2019-6956

Global buffer overflow in the function ps_mix_phase (libfaad/ps_dec.c). This vulnerability might allow remote attackers to cause denial of service or any other unspecified impact via crafted MPEG AAC data.

CVE-2019-15296

Buffer overflow in the function faad_resetbits (libfaad/bits.c). This vulnerability might allow remote attackers to cause denial of service via crafted MPEG AAC data.

For Debian 8 Jessie, these problems have been fixed in version 2.7-8+deb8u3.

We recommend that you upgrade your faad2 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'faad2' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"faad", ver:"2.7-8+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"faad2-dbg", ver:"2.7-8+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfaad-dev", ver:"2.7-8+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfaad2", ver:"2.7-8+deb8u3", rls:"DEB8"))) {
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
