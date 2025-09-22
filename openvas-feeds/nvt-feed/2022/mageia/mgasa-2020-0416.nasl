# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0416");
  script_cve_id("CVE-2020-26164");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 14:11:49 +0000 (Tue, 20 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0416)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0416");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0416.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27349");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20201002-1.txt");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/10/13/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdeconnect-kde' package(s) announced via the MGASA-2020-0416 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker on your local network could send maliciously crafted packets to
other hosts running kdeconnect on the network, causing them to use large
amounts of CPU, memory or network connections, which could be used in a Denial
of Service attack within the network.
(CVE-2020-26164)");

  script_tag(name:"affected", value:"'kdeconnect-kde' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde", rpm:"kdeconnect-kde~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde-handbook", rpm:"kdeconnect-kde-handbook~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde-nautilus", rpm:"kdeconnect-kde-nautilus~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectcore1", rpm:"lib64kdeconnectcore1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectinterfaces1", rpm:"lib64kdeconnectinterfaces1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectpluginkcm1", rpm:"lib64kdeconnectpluginkcm1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectcore1", rpm:"libkdeconnectcore1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectinterfaces1", rpm:"libkdeconnectinterfaces1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectpluginkcm1", rpm:"libkdeconnectpluginkcm1~1.3.4~2.1.mga7", rls:"MAGEIA7"))) {
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
