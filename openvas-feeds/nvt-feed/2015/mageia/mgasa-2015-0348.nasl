# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130039");
  script_cve_id("CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5196", "CVE-2015-5219");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:52 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 13:48:34 +0000 (Thu, 27 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0348");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0348.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/08/25/3");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#June_2015_NTP_Security_Vulnerabi");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16322");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2015-0348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ntp packages fix security vulnerability:

A flaw was found in the way ntpd processed certain remote configuration
packets. An attacker could use a specially crafted package to cause ntpd to
crash if the attacker had authenticated access to remote ntpd configuration
(CVE-2015-5146).

It was found that ntpd could crash due to an uninitialized variable when
processing malformed logconfig configuration commands, for example,
ntpq -c ':config logconfig a' (CVE-2015-5194).

It was found that ntpd exits with a segmentation fault when a statistics
type that was not enabled during compilation (e.g. timingstats) is
referenced by the statistics or filegen configuration command, for example,
ntpq -c ':config statistics timingstats'
ntpq -c ':config filegen timingstats' (CVE-2015-5195).

It was found that the :config command can be used to set the pidfile and
driftfile paths without any restrictions. A remote attacker could use
this flaw to overwrite a file on the file system with a file containing
the pid of the ntpd process (immediately) or the current estimated drift
of the system clock (in hourly intervals). For example,
ntpq -c ':config pidfile /tmp/ntp.pid'
ntpq -c ':config driftfile /tmp/ntp.drift' (CVE-2015-5196).

It was discovered that sntp would hang in an infinite loop when a
crafted NTP packet was received, related to the conversion of the
precision value in the packet to double (CVE-2015-5219).");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~15.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~15.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~15.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.1.mga5", rls:"MAGEIA5"))) {
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
