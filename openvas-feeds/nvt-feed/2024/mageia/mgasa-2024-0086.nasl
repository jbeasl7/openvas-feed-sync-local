# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0086");
  script_cve_id("CVE-2022-29167");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 16:58:31 +0000 (Mon, 16 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0086");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0086.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31313");
  script_xref(name:"URL", value:"https://github.com/mozilla/hawk/security/advisories/GHSA-44pw-h2cw-w3vq");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6116-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3246");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs-hawk' package(s) announced via the MGASA-2024-0086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hawk is an HTTP authentication scheme providing mechanisms for making
authenticated HTTP requests with partial cryptographic verification of
the request and response, covering the HTTP method, request URI, host,
and optionally the request payload. Hawk used a regular expression to
parse `Host` HTTP header (`Hawk.utils.parseHost()`), which was subject
to regular expression DoS attack - meaning each added character in the
attacker's input increases the computation time exponentially.
`parseHost()` was patched in `9.0.1` to use built-in `URL` class to
parse hostname instead. `Hawk.authenticate()` accepts `options`
argument. If that contains `host` and `port`, those would be used
instead of a call to `utils.parseHost()`. (CVE-2022-29167)");

  script_tag(name:"affected", value:"'nodejs-hawk' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs-hawk", rpm:"nodejs-hawk~7.0.10~4.1.mga9", rls:"MAGEIA9"))) {
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
