# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0244");
  script_cve_id("CVE-2019-16275");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-13 16:48:45 +0000 (Fri, 13 Sep 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0244)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0244");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0244.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/ishow_bug.cgi?id=25430");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/36G4XAZ644DMHBLKOL4FDSPZVIGNQY6U/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FEGITWRTIWABW54ANEPCEF4ARZLXGSK5/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-7/ap-mode-pmf-disconnection-protection-bypass.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd, wpa_supplicant' package(s) announced via the MGASA-2020-0244 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wpa_supplicant and hostpad packages fix security vulnerability:

A vulnerability was discovered in wpa_supplicant. When Access Point (AP)
mode and Protected Management Frames (PMF) (IEEE 802.11w) are enabled,
wpa_supplicant does not perform enough validation on the source address
of some received management frames. An attacker within the 802.11
communications range could use this flaw to inject an unauthenticated
frame and perform a denial-of-service attack against another device which
would be disconnected from the network (CVE-2019-16275).");

  script_tag(name:"affected", value:"'hostapd, wpa_supplicant' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.9~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.9~1.2.mga7", rls:"MAGEIA7"))) {
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
