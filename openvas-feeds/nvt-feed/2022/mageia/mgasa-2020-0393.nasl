# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0393");
  script_cve_id("CVE-2020-25829");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-21 14:57:53 +0000 (Wed, 21 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0393");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0393.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27400");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/changelog/4.1.html#change-4.1.18");
  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-07.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns-recursor' package(s) announced via the MGASA-2020-0393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in PowerDNS Recursor before 4.1.18, 4.2.x before 4.2.5,
and 4.3.x before 4.3.5. A remote attacker can cause the cached records for a
given name to be updated to the Bogus DNSSEC validation state, instead of
their actual DNSSEC Secure state, via a DNS ANY query. This results in a
denial of service for installation that always validate (dnssec=validate),
and for clients requesting validation when on-demand validation is enabled
(dnssec=process). (CVE-2020-25829)");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.1.18~1.mga7", rls:"MAGEIA7"))) {
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
