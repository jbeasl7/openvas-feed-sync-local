# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0134");
  script_cve_id("CVE-2017-6451", "CVE-2017-6458", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-30 14:10:56 +0000 (Thu, 30 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0134)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0134");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0134.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#March_2017_ntp_4_2_8p10_NTP_Secu");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20595");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4B7BMVXV53EE7XYW2KAVETDHTP452O3Z/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2017-0134 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in NTP, in the legacy MX4200 refclock
implementation. If this refclock was compiled in and used, an attacker may
be able to induce stack overflow, leading to a crash or potential code
execution (CVE-2017-6451).

A vulnerability was found in NTP, in the building of response packets with
custom fields. If custom fields were configured in ntp.conf with
particularly long names, inclusion of these fields in the response packet
could cause a buffer overflow, leading to a crash (CVE-2017-6458).

A vulnerability was found in NTP, in the parsing of packets from the
/dev/datum device. A malicious device could send crafted messages, causing
ntpd to crash (CVE-2017-6462).

A vulnerability was discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause
ntpd to crash by sending a crafted message (CVE-2017-6463).

A vulnerability was discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause
ntpd to crash by sending a crafted message (CVE-2017-6464).");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.8.mga5", rls:"MAGEIA5"))) {
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
