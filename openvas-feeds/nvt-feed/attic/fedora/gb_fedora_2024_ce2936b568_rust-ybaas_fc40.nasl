# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886585");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-05-27 10:43:23 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for rust-ybaas (FEDORA-2024-ce2936b568)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ce2936b568");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/W3PEXBHDRYEDMXWBIQ6OADMX5CC356DB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-ybaas'
  package(s) announced via the FEDORA-2024-ce2936b568 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Don&#39,t you love when you accidentally tap your Yubikey when you have your
IRC client in focus and you send 987947 into Libera? Want to be able to
have that experience without having to reach all the way over to your
laptop&#39,s USB port? Don&#39,t want the complexity of installing and using the
yubibomb CLI tool? Now you can use yubibomb as a service!");

  script_tag(name:"affected", value:"'rust-ybaas' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
