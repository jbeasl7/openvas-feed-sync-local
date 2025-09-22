# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123690");
  script_cve_id("CVE-2012-1182");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0515)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0515");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0515.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-mapi, openchange' package(s) announced via the ELSA-2013-0515 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"evolution-mapi
[0.28.3-12]
- Add patch for RH bug #903241 (Double-free on message copy/move)

[0.28.3-11]
- Add patch for RH bug #902932 (Cannot connect with latest samba)

[0.28.3-10]
- Drop multilib by obsoleting evolution-mapi < 0.28.3-9 (RH bug #886914).

[0.28.3-9]
- Adapt to OpenChange 1.0 (RH bug #767678).

[0.28.3-8]
- Add patch for RH bug #680061 (crash while setting props).

openchange
[1.0-4]
- Use current version (1.0-4) for a multilib obsolete (RH bug #881698).

[1.0-3]
- Add patch to be able to send large messages (RH bug #870405)

[1.0-2]
- Drop multilib by obsoleting openchange < 0.9 (RH bug #881698).

[1.0-1]
- Rebase to 1.0 using the rpm spec from Fedora 18.");

  script_tag(name:"affected", value:"'evolution-mapi, openchange' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"evolution-mapi", rpm:"evolution-mapi~0.28.3~12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-mapi-devel", rpm:"evolution-mapi-devel~0.28.3~12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange", rpm:"openchange~1.0~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-client", rpm:"openchange-client~1.0~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-devel", rpm:"openchange-devel~1.0~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-devel-docs", rpm:"openchange-devel-docs~1.0~4.el6", rls:"OracleLinux6"))) {
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
