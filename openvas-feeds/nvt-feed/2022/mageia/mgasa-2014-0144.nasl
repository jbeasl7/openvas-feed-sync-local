# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0144");
  script_cve_id("CVE-2014-0016");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0144)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0144");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0144.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12943");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1072180");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel' package(s) announced via the MGASA-2014-0144 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way stunnel, a socket wrapper which can provide
SSL support to ordinary applications, performed (re)initialization of PRNG
after fork. When accepting a new connection, the server forks and the
child process handles the request. The RAND_bytes() function of openssl
doesn't reset its state after the fork, but seeds the PRNG with the output
of time(NULL). The most important consequence is that servers using EC
(ECDSA) or DSA certificates may under certain conditions leak their
private key (CVE-2014-0016).

The updated packages fix this issue by using threads instead of new
processes to handle connections.

Also an issue has been corrected where the directory for the pid file was
not being created when the package is installed.

An issue currently exists in Mageia 4 where it fails trying to use FIPS SSL
(mga#13124). This can be worked around by adding fips = no into the config.");

  script_tag(name:"affected", value:"'stunnel' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~4.55~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~4.56~3.2.mga4", rls:"MAGEIA4"))) {
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
