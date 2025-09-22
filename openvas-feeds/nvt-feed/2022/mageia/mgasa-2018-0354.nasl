# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0354");
  script_cve_id("CVE-2018-12019", "CVE-2018-12020");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 19:33:08 +0000 (Wed, 01 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0354");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0354.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23415");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00050.html");
  script_xref(name:"URL", value:"https://www.enigmail.net/index.php/en/download/changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the MGASA-2018-0354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated thunderbird package fixes security vulnerabilities:

* Spoofing of Email signatures II: The signature verification routine in
 Enigmail interpreted User IDs as status/control messages and did not
 correctly keep track of the status of multiple signatures. This allowed
 remote attackers to spoof arbitrary email signatures via public keys
 containing crafted primary user ids (CVE-2018-12019).

* Spoofing of Email signatures I: GnuPG 2.2.8 fixed a security bug that
 allows remote attackers to spoof arbitrary email signatures via the
 embedded '--filename' parameter in OpenPGP literal data packets. This
 release of Enigmail prevents the exploit for all versions of GnuPG,
 i.e. also if GnuPG is not updated (CVE-2018-12020).");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~52.9.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~52.9.1~1.1.mga6", rls:"MAGEIA6"))) {
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
