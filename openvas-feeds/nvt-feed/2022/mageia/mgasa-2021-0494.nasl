# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0494");
  script_cve_id("CVE-2021-3429");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-04 13:00:46 +0000 (Thu, 04 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2021-0494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0494");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0494.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28991");
  script_xref(name:"URL", value:"https://github.com/canonical/cloud-init/releases/tag/21.2");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2601");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cloud-init' package(s) announced via the MGASA-2021-0494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cloud-init has the ability to generate and set a randomized password for
system users. This functionality is enabled at runtime by passing
cloud-config data such as: 'chpasswd: list: <pipe> user1:RANDOM'

When instructing cloud-init to set a random password for a new user
account, versions before 21.1.19 would write that password to the
world-readable log file /var/log/cloud-init-output.log. This could allow a
local user to log in as another user (CVE-2021-3429).");

  script_tag(name:"affected", value:"'cloud-init' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"cloud-init", rpm:"cloud-init~20.2~2.1.mga8", rls:"MAGEIA8"))) {
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
