Name:           yara-cryptex
Version:        0.1.0
Release:        1%{?dist}
Summary:        YARA Cryptex Dictionary System
License:        Apache-2.0
URL:            https://github.com/pyro-platform/yara-cryptex
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
Requires:       libc

%description
Complete YARA Cryptex dictionary with 587 entries, feed scanner,
and API server. Provides command-line tools and REST API for
YARA function mapping and rule discovery.

%prep
%setup -q

%build
cd rust
cargo build --release

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/yara-cryptex
mkdir -p %{buildroot}/var/lib/yara-cryptex

install -m 755 rust/cryptex-cli/target/release/cryptex %{buildroot}/usr/bin/
install -m 755 rust/cryptex-api/target/release/cryptex-api %{buildroot}/usr/bin/
install -m 755 rust/yara-feed-scanner/target/release/yara-feed-scanner %{buildroot}/usr/bin/
install -m 644 data/cryptex.json %{buildroot}/etc/yara-cryptex/

%files
/usr/bin/cryptex
/usr/bin/cryptex-api
/usr/bin/yara-feed-scanner
/etc/yara-cryptex/cryptex.json

%changelog
* Fri Nov 22 2025 PYRO Platform <pyro@example.com> - 0.1.0-1
- Initial release

