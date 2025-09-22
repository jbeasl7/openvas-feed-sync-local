# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0347");
  script_cve_id("CVE-2024-37891");
  script_tag(name:"creation_date", value:"2024-11-11 04:11:21 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0347");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0347.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33716");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-urllib3' package(s) announced via the MGASA-2024-0347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When using urllib3's proxy support with ProxyManager, the
Proxy-Authorization header is only sent to the configured proxy, as
expected.
However, when sending HTTP requests without using urllib3's proxy
support, it's possible to accidentally configure the Proxy-Authorization
header even though it won't have any effect as the request is not using
a forwarding proxy or a tunneling proxy. In those cases, urllib3 doesn't
treat the Proxy-Authorization HTTP header as one carrying authentication
material and thus doesn't strip the header on cross-origin redirects.
Because this is a highly unlikely scenario, we believe the severity of
this vulnerability is low for almost all users. Out of an abundance of
caution urllib3 will automatically strip the Proxy-Authorization header
during cross-origin redirects to avoid the small chance that users are
doing this on accident.
Users should use urllib3's proxy support or disable automatic redirects
to achieve safe processing of the Proxy-Authorization header, but we
still decided to strip the header by default in order to further protect
users who aren't using the correct approach.");

  script_tag(name:"affected", value:"'python-urllib3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.26.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3+brotli", rpm:"python3-urllib3+brotli~1.26.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3+socks", rpm:"python3-urllib3+socks~1.26.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.26.20~1.mga9", rls:"MAGEIA9"))) {
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
