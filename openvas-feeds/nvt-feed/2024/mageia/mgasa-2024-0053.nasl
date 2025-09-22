# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0053");
  script_cve_id("CVE-2023-52160");
  script_tag(name:"creation_date", value:"2024-03-07 04:12:20 +0000 (Thu, 07 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-04 22:47:18 +0000 (Mon, 04 Mar 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0053");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0053.html");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.383534");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32911");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2024/02/msg00013.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N46C4DTVUWK336OYDA4LGALSC5VVPTCC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the MGASA-2024-0053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
The implementation of PEAP in wpa_supplicant through 2.10 allows
authentication bypass. For a successful attack, wpa_supplicant must be
configured to not verify the network's TLS certificate during Phase 1
authentication, and an eap_peap_decrypt vulnerability can then be abused
to skip Phase 2 authentication. The attack vector is sending an EAP-TLV
Success packet instead of starting Phase 2. This allows an adversary to
impersonate Enterprise Wi-Fi networks.
(CVE-2023-52160)");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.10~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.10~3.1.mga9", rls:"MAGEIA9"))) {
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
