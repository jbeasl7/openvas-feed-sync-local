# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131100");
  script_cve_id("CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7871");
  script_tag(name:"creation_date", value:"2015-10-26 07:35:58 +0000 (Mon, 26 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0413");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0413.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#October_2015_NTP_Security_Vulner");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16999");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2015-0413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that ntpd did not correctly implement the threshold
limitation for the '-g' option, which is used to set the time without any
restrictions.

A man-in-the-middle attacker able to intercept NTP traffic between a
connecting client and an NTP server could use this flaw to force that
client to make multiple steps larger than the panic threshold, effectively
changing the time to an arbitrary value at any time (CVE-2015-5300).

Slow memory leak in CRYPTO_ASSOC with autokey (CVE-2015-7701).

Incomplete autokey data packet length checks could result in crash caused
by a crafted packet (CVE-2015-7691, CVE-2015-7692, CVE-2015-7702).

Clients that receive a KoD should validate the origin timestamp field
(CVE-2015-7704).

ntpq atoascii() Memory Corruption Vulnerability could result in ntpd crash
caused by a crafted packet (CVE-2015-7852).

Symmetric association authentication bypass via crypto-NAK
(CVE-2015-7871).");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.2.mga5", rls:"MAGEIA5"))) {
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
