# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0286");
  script_cve_id("CVE-2024-7347");
  script_tag(name:"creation_date", value:"2024-09-11 04:13:15 +0000 (Wed, 11 Sep 2024)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 15:42:32 +0000 (Fri, 05 Sep 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0286");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0286.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33509");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2024/08/14/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the MGASA-2024-0286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-7347: NGINX Open Source and NGINX Plus have a vulnerability in
the ngx_http_mp4_module, which might allow an attacker to over-read
NGINX worker memory resulting in its termination, using a specially
crafted mp4 file. The issue only affects NGINX if it is built with the
ngx_http_mp4_module and the mp4 directive is used in the configuration
file. Additionally, the attack is possible only if an attacker can
trigger the processing of a specially crafted mp4 file with the
ngx_http_mp4_module. Note: Software versions which have reached End of
Technical Support (EoTS) are not evaluated.");

  script_tag(name:"affected", value:"'nginx' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.26.2~1.mga9", rls:"MAGEIA9"))) {
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
