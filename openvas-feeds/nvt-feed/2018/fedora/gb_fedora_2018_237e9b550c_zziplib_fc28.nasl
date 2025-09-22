# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874880");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-08-02 06:04:25 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2018-6541", "CVE-2018-7727", "CVE-2017-5974", "CVE-2017-5975",
                "CVE-2017-5976", "CVE-2017-5977", "CVE-2017-5978", "CVE-2017-5979",
                "CVE-2017-5980", "CVE-2017-5981", "CVE-2018-7726");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for zziplib FEDORA-2018-237e9b550c");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'zziplib'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"affected", value:"zziplib on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-237e9b550c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I6J523IVLVVPUEHRDYT54A5QOKM5XVTO");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC28");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"zziplib", rpm:"zziplib~0.13.69~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
