# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840959");
  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_tag(name:"creation_date", value:"2012-03-26 08:47:20 +0000 (Mon, 26 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1403-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1403-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1403-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the USN-1403-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed BDF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause FreeType to crash. (CVE-2012-1126)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed BDF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause FreeType to crash. (CVE-2012-1127)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed TrueType font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash.
(CVE-2012-1128)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed Type42 font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash.
(CVE-2012-1129)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed PCF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause FreeType to crash. (CVE-2012-1130)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed TrueType font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash.
(CVE-2012-1131)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed Type1 font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash.
(CVE-2012-1132)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed BDF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause FreeType to crash or possibly execute
arbitrary code with user privileges. (CVE-2012-1133)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed Type1 font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash or possibly
execute arbitrary code with user privileges. (CVE-2012-1134)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed TrueType font files. If a user were tricked into using a specially
crafted font file, a remote attacker could cause FreeType to crash.
(CVE-2012-1135)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed BDF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause FreeType to crash or possibly execute
arbitrary code with user privileges. (CVE-2012-1136)

Mateusz Jurczyk discovered that FreeType did not correctly handle certain
malformed BDF font files. If a user were tricked into using a specially crafted
font file, a remote attacker could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freetype' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.11-1ubuntu2.6", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.2-2ubuntu0.4", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.4-1ubuntu2.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.4-2ubuntu1.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.3.5-1ubuntu4.8.04.9", rls:"UBUNTU8.04 LTS"))) {
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
