# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0195");
  script_cve_id("CVE-2016-1549", "CVE-2018-7170", "CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184", "CVE-2018-7185");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-28 22:19:44 +0000 (Wed, 28 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0195.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#Recent_Vulnerabilities");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22850");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2018-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release addresses five security issues in ntpd for Mageia 6:

LOW/MEDIUM: Sec 3012 / CVE-2016-1549 / VU#961909: Sybil vulnerability:
ephemeral association attack While fixed in ntp-4.2.8p7, there are
significant additional protections for this issue in 4.2.8p11.
Reported by Matt Van Gundy of Cisco.

INFO/MEDIUM: Sec 3412 / CVE-2018-7182 / VU#961909: ctl_getitem(): buffer
read overrun leads to undefined behavior and information leak
Reported by Yihan Lian of Qihoo 360.

LOW: Sec 3415 / CVE-2018-7170 / VU#961909: Multiple authenticated
ephemeral associations. Reported on the questions@ list.

LOW: Sec 3453 / CVE-2018-7184 / VU#961909: Interleaved symmetric mode
cannot recover from bad state. Reported by Miroslav Lichvar of Red Hat.

LOW/MEDIUM: Sec 3454 / CVE-2018-7185 / VU#961909: Unauthenticated packet
can reset authenticated interleaved association.
Reported by Miroslav Lichvar of Red Hat.

one security issue in ntpq:
MEDIUM: Sec 3414 / CVE-2018-7183 / VU#961909: ntpq:decodearr() can write
beyond its buffer limit. Reported by Michael Macnair of Thales-esecurity.com.

and provides over 33 bugfixes and 32 other improvements. ENotification
of these issues were delivered to our Institutional members on a rolling
basis as they were reported and as progress was made.");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p11~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p11~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.8p11~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.8p11~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.8p11~1.mga6", rls:"MAGEIA6"))) {
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
