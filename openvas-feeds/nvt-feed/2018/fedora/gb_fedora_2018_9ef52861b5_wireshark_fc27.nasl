# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874872");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-08-02 06:01:38 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342",
                "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368",
                "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-7419", "CVE-2018-7418",
                "CVE-2018-7417", "CVE-2018-7420", "CVE-2018-7320", "CVE-2018-7336",
                "CVE-2018-7337", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-6836",
                "CVE-2018-5335", "CVE-2018-5334", "CVE-2017-6014", "CVE-2017-9616",
                "CVE-2017-9617", "CVE-2017-9766", "CVE-2017-17935", "CVE-2017-17085",
                "CVE-2017-17084", "CVE-2017-17083", "CVE-2017-15189", "CVE-2017-15190",
                "CVE-2017-15191", "CVE-2017-15192", "CVE-2017-15193", "CVE-2017-13764",
                "CVE-2017-13765", "CVE-2017-13766", "CVE-2017-13767");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for wireshark FEDORA-2018-9ef52861b5");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"wireshark on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-9ef52861b5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AM62HSZGLJTWME5BBTQHN5RW6HL3PMPQ");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.6.2~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
