# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130015");
  script_cve_id("CVE-2015-5234", "CVE-2015-5235");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:33 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0376");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0376.html");
  script_xref(name:"URL", value:"http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2015-September/033546.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16755");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1233667");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1233697");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the MGASA-2015-0376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated icedtea-web packages fix security vulnerabilities:

It was discovered that IcedTea-Web did not properly sanitize applet URLs when
storing applet trust settings. A malicious web page could use this flaw to
inject trust-settings configuration, and cause applets to be executed without
user approval (CVE-2015-5234).

It was discovered that IcedTea-Web did not properly determine an applet's
origin when asking the user if the applet should be run. A malicious page
could use this flaw to cause IcedTea-Web to execute the applet without user
approval, or confuse the user into approving applet execution based on an
incorrectly indicated applet origin (CVE-2015-5235).");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.5.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.5.3~1.mga5", rls:"MAGEIA5"))) {
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
