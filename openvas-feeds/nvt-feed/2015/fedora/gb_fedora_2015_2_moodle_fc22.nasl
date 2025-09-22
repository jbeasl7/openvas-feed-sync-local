# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806906");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-12-12 05:41:41 +0100 (Sat, 12 Dec 2015)");
  script_cve_id("CVE-2015-5331", "CVE-2015-5332", "CVE-2015-5335", "CVE-2015-5336",
                "CVE-2015-5337", "CVE-2015-5338", "CVE-2015-5339", "CVE-2015-5340",
                "CVE-2015-5341", "CVE-2015-5342", "CVE-2015-5264", "CVE-2015-5265",
                "CVE-2015-5266", "CVE-2015-5267", "CVE-2015-5272", "CVE-2015-5268",
                "CVE-2015-5269");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:54:00 +0000 (Tue, 01 Dec 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for moodle FEDORA-2015-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"moodle on Fedora 22");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-December/173666.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC22");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.9~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
